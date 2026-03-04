use crate::err::{ChunkError, EvtxError, InputError, Result};

use crate::evtx_chunk::{EVTX_CHUNK_HEADER_SIZE, EvtxChunkData, EvtxChunkHeader};
use crate::evtx_file_header::EvtxFileHeader;
use crate::evtx_record::SerializedEvtxRecord;
use bumpalo::Bump;
#[cfg(feature = "multithreading")]
use rayon::prelude::*;

use log::trace;
#[cfg(not(feature = "multithreading"))]
use log::warn;

use log::{debug, info};
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use crate::EvtxRecord;
use encoding::EncodingRef;
use encoding::all::WINDOWS_1252;
use std::cmp::max;
use std::fmt;
use std::fmt::Debug;
use std::iter::{IntoIterator, Iterator};
use std::path::Path;
use std::sync::Arc;

pub const EVTX_CHUNK_SIZE: usize = 65536;
pub const EVTX_FILE_HEADER_SIZE: usize = 4096;

// Stable shim until https://github.com/rust-lang/rust/issues/59359 is merged.
// Taken from proposed std code.
pub trait ReadSeek: Read + Seek {
    fn tell(&mut self) -> io::Result<u64> {
        self.stream_position()
    }
    fn stream_len(&mut self) -> io::Result<u64> {
        let old_pos = self.tell()?;
        let len = self.seek(SeekFrom::End(0))?;

        // Avoid seeking a third time when we were already at the end of the
        // stream. The branch is usually way cheaper than a seek operation.
        if old_pos != len {
            self.seek(SeekFrom::Start(old_pos))?;
        }

        Ok(len)
    }
}

impl<T: Read + Seek> ReadSeek for T {}

/// Wraps a single `EvtxFileHeader`.
///
///
/// Example usage (single threaded):
///
/// ```rust
/// # use evtx::EvtxParser;
/// # let fp = std::path::PathBuf::from(format!("{}/samples/security.evtx", std::env::var("CARGO_MANIFEST_DIR").unwrap()));
///
///
/// let mut parser = EvtxParser::from_path(fp).unwrap();
///
/// for record in parser.records() {
///     match record {
///         Ok(r) => println!("Record {}\n{}", r.event_record_id, r.data),
///         Err(e) => eprintln!("{}", e),
///     }
/// }
///
///
/// ```
/// Example usage (multi-threaded):
///
/// ```rust
/// # use evtx::{EvtxParser, ParserSettings};
/// # let fp = std::path::PathBuf::from(format!("{}/samples/security.evtx", std::env::var("CARGO_MANIFEST_DIR").unwrap()));
///
///
/// let settings = ParserSettings::default().num_threads(0);
/// let mut parser = EvtxParser::from_path(fp).unwrap().with_configuration(settings);
///
/// for record in parser.records() {
///     match record {
///         Ok(r) => println!("Record {}\n{}", r.event_record_id, r.data),
///         Err(e) => eprintln!("{}", e),
///     }
/// }
///
/// ```
///
pub struct EvtxParser<T: ReadSeek> {
    data: T,
    header: EvtxFileHeader,
    config: Arc<ParserSettings>,
    /// The calculated_chunk_count is the: (<file size> - <header size>) / <chunk size>
    /// This is needed because the chunk count of an EVTX file can be larger than the u16
    /// value stored in the file header.
    calculated_chunk_count: u64,
}
impl<T: ReadSeek> Debug for EvtxParser<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::fmt::Result {
        f.debug_struct("EvtxParser")
            .field("header", &self.header)
            .field("config", &self.config)
            .finish()
    }
}

#[derive(Clone)]
pub struct ParserSettings {
    /// Controls the number of threads used for parsing chunks concurrently.
    num_threads: usize,
    /// If enabled, chunk with bad checksums will be skipped.
    validate_checksums: bool,
    /// If enabled, XML attributes will be separated in JSON
    /// into a separate field. Example:
    /// {
    ///   "EventID": {
    ///     "#attributes": {
    ///       "Qualifiers": 16384
    ///     },
    ///     "#text": 4111
    ///   }
    /// }
    ///
    /// Becomes:
    /// {
    ///   "EventID": 4111,
    ///   "EventID_attributes": {
    ///     "Qualifiers": 16384
    ///   }
    /// }
    separate_json_attributes: bool,
    /// If true, output will be indented.
    indent: bool,
    /// Controls the ansi codec used to deserialize ansi strings inside the xml document.
    ansi_codec: EncodingRef,
    /// Optional offline WEVT template cache used as a fallback when embedded EVTX templates
    /// are missing/corrupt (common in carved/dirty logs).
    #[cfg(feature = "wevt_templates")]
    wevt_cache: Option<Arc<crate::wevt_templates::WevtCache>>,
}

impl Debug for ParserSettings {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::fmt::Result {
        let mut ds = f.debug_struct("ParserSettings");
        ds.field("num_threads", &self.num_threads)
            .field("validate_checksums", &self.validate_checksums)
            .field("separate_json_attributes", &self.separate_json_attributes)
            .field("indent", &self.indent)
            .field("ansi_codec", &self.ansi_codec.name());

        #[cfg(feature = "wevt_templates")]
        ds.field("wevt_cache", &self.wevt_cache.is_some());

        ds.finish()
    }
}

impl PartialEq for ParserSettings {
    fn eq(&self, other: &ParserSettings) -> bool {
        self.ansi_codec.name() == other.ansi_codec.name()
            && self.num_threads == other.num_threads
            && self.validate_checksums == other.validate_checksums
            && self.separate_json_attributes == other.separate_json_attributes
            && self.indent == other.indent
    }
}

impl Default for ParserSettings {
    fn default() -> Self {
        ParserSettings {
            num_threads: 0,
            validate_checksums: false,
            separate_json_attributes: false,
            indent: true,
            ansi_codec: WINDOWS_1252,
            #[cfg(feature = "wevt_templates")]
            wevt_cache: None,
        }
    }
}

impl ParserSettings {
    pub fn new() -> Self {
        ParserSettings::default()
    }

    /// Sets the number of worker threads.
    /// `0` will let rayon decide.
    ///
    #[cfg(feature = "multithreading")]
    pub fn num_threads(mut self, num_threads: usize) -> Self {
        self.num_threads = if num_threads == 0 {
            rayon::current_num_threads()
        } else {
            num_threads
        };
        self
    }

    /// Does nothing and emits a warning when complied without multithreading.
    #[cfg(not(feature = "multithreading"))]
    pub fn num_threads(mut self, _num_threads: usize) -> Self {
        warn!("Setting num_threads has no effect when compiling without multithreading support.");

        self.num_threads = 1;
        self
    }

    /// Sets the ansi codec used by the parser.
    pub fn ansi_codec(mut self, ansi_codec: EncodingRef) -> Self {
        self.ansi_codec = ansi_codec;

        self
    }

    /// Attach an offline WEVT template cache used as a fallback during parsing.
    #[cfg(feature = "wevt_templates")]
    pub fn wevt_cache(mut self, cache: Option<Arc<crate::wevt_templates::WevtCache>>) -> Self {
        self.wevt_cache = cache;
        self
    }

    pub fn validate_checksums(mut self, validate_checksums: bool) -> Self {
        self.validate_checksums = validate_checksums;

        self
    }

    pub fn separate_json_attributes(mut self, separate: bool) -> Self {
        self.separate_json_attributes = separate;

        self
    }

    pub fn indent(mut self, pretty: bool) -> Self {
        self.indent = pretty;

        self
    }

    /// Gets the current ansi codec
    pub fn get_ansi_codec(&self) -> EncodingRef {
        self.ansi_codec
    }

    #[cfg(feature = "wevt_templates")]
    pub(crate) fn get_wevt_cache(&self) -> Option<&Arc<crate::wevt_templates::WevtCache>> {
        self.wevt_cache.as_ref()
    }

    pub fn should_separate_json_attributes(&self) -> bool {
        self.separate_json_attributes
    }

    pub fn should_indent(&self) -> bool {
        self.indent
    }

    pub fn should_validate_checksums(&self) -> bool {
        self.validate_checksums
    }

    pub fn get_num_threads(&self) -> &usize {
        &self.num_threads
    }
}

impl EvtxParser<File> {
    /// Attempts to load an evtx file from a given path, will fail if the path does not exist,
    /// or if evtx header is invalid.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path
            .as_ref()
            .canonicalize()
            .map_err(|e| InputError::failed_to_open_file(e, &path))?;

        let f = File::open(&path).map_err(|e| InputError::failed_to_open_file(e, &path))?;

        let cursor = f;
        Self::from_read_seek(cursor)
    }
}

impl EvtxParser<Cursor<Vec<u8>>> {
    /// Attempts to load an evtx file from a given path, will fail the evtx header is invalid.
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self> {
        let cursor = Cursor::new(buffer);
        Self::from_read_seek(cursor)
    }
}

impl<T: ReadSeek> EvtxParser<T> {
    pub fn from_read_seek(mut read_seek: T) -> Result<Self> {
        let evtx_header = EvtxFileHeader::from_stream(&mut read_seek)?;

        // Because an event log can be larger than u16 MAX * EVTX_CHUNK_SIZE,
        // We need to calculate the chunk count instead of using the header value
        // this allows us to continue parsing events past the 4294901760 bytes of
        // chunk data
        let stream_size = ReadSeek::stream_len(&mut read_seek)?;
        let chunk_data_size: u64 =
            match stream_size.checked_sub(evtx_header.header_block_size.into()) {
                Some(c) => c,
                None => {
                    return Err(EvtxError::calculation_error(format!(
                        "Could not calculate valid chunk count because stream size is less \
                            than evtx header block size. (stream_size: {}, header_block_size: {})",
                        stream_size, evtx_header.header_block_size
                    )));
                }
            };
        let chunk_count = chunk_data_size / EVTX_CHUNK_SIZE as u64;

        debug!("EVTX Header: {:#?}", evtx_header);
        Ok(EvtxParser {
            data: read_seek,
            header: evtx_header,
            config: Arc::new(ParserSettings::default()),
            calculated_chunk_count: chunk_count,
        })
    }

    pub fn with_configuration(mut self, configuration: ParserSettings) -> Self {
        self.config = Arc::new(configuration);
        self
    }

    /// Returns the number of chunks in the file, calculated from the file size.
    pub fn chunk_count(&self) -> u64 {
        self.calculated_chunk_count
    }

    /// Read only the 512-byte chunk header at the given chunk number,
    /// without reading the full 64KB chunk data.
    fn read_chunk_header(&mut self, chunk_number: u64) -> Result<Option<EvtxChunkHeader>> {
        let chunk_offset =
            EVTX_FILE_HEADER_SIZE as u64 + chunk_number * EVTX_CHUNK_SIZE as u64;

        self.data
            .seek(SeekFrom::Start(chunk_offset))
            .map_err(|e| EvtxError::FailedToParseChunk {
                chunk_id: chunk_number,
                source: Box::new(ChunkError::FailedToSeekToChunk(e)),
            })?;

        let mut header_data = [0u8; EVTX_CHUNK_HEADER_SIZE];
        let amount_read = self
            .data
            .read(&mut header_data)
            .map_err(|_| EvtxError::incomplete_chunk(chunk_number))?;

        if amount_read < EVTX_CHUNK_HEADER_SIZE {
            return Err(EvtxError::incomplete_chunk(chunk_number));
        }

        if header_data.iter().all(|&x| x == 0) {
            return Ok(None);
        }

        EvtxChunkHeader::from_bytes(&header_data)
            .map(Some)
            .map_err(|e| EvtxError::FailedToParseChunk {
                chunk_id: chunk_number,
                source: Box::new(ChunkError::FailedToParseChunkHeader(e)),
            })
    }

    /// Scans chunk headers backward from the end of the file to determine the
    /// starting chunk and record skip count needed to yield exactly `num_records`
    /// records from the tail of the file.
    ///
    /// Returns `(start_chunk, skip_count)` where `start_chunk` is the chunk
    /// number to begin iterating from and `skip_count` is how many records to
    /// skip from that chunk to yield exactly `num_records`.
    fn find_tail_start_chunk(&mut self, num_records: usize) -> (u64, usize) {
        if self.calculated_chunk_count == 0 {
            return (0, 0);
        }

        let mut accumulated: usize = 0;
        let mut earliest_chunk: u64 = self.calculated_chunk_count.saturating_sub(1);

        for chunk_num in (0..self.calculated_chunk_count).rev() {
            match self.read_chunk_header(chunk_num) {
                Ok(Some(header)) => {
                    let records_in_chunk =
                        (header.last_event_record_id - header.first_event_record_id + 1) as usize;
                    accumulated += records_in_chunk;
                    earliest_chunk = chunk_num;

                    if accumulated >= num_records {
                        let skip = accumulated - num_records;
                        return (earliest_chunk, skip);
                    }
                }
                // Skip empty or unreadable chunks
                Ok(None) | Err(_) => continue,
            }
        }

        // File has fewer than num_records records total
        (earliest_chunk, 0)
    }

    /// Allocate a new chunk from the given data, at the offset expected by `chunk_number`.
    /// If the read chunk contains valid data, an `Ok(Some(EvtxChunkData))` will be returned.
    /// If the read chunk contains invalid data (bad magic, bad checksum when `validate_checksum` is set to true),
    /// of if not enough data can be read (e.g. because we reached EOF), an `Err` is returned.
    /// If the read chunk is empty, `Ok(None)` will be returned.
    fn allocate_chunk(
        data: &mut T,
        chunk_number: u64,
        validate_checksum: bool,
    ) -> Result<Option<EvtxChunkData>> {
        let mut chunk_data = Vec::with_capacity(EVTX_CHUNK_SIZE);
        let chunk_offset = EVTX_FILE_HEADER_SIZE + chunk_number as usize * EVTX_CHUNK_SIZE;

        trace!(
            "Offset `0x{:08x} ({})` - Reading chunk number `{}`",
            chunk_offset, chunk_offset, chunk_number
        );

        data.seek(SeekFrom::Start(chunk_offset as u64))
            .map_err(|e| EvtxError::FailedToParseChunk {
                chunk_id: chunk_number,
                source: Box::new(ChunkError::FailedToSeekToChunk(e)),
            })?;

        let amount_read = data
            .take(EVTX_CHUNK_SIZE as u64)
            .read_to_end(&mut chunk_data)
            .map_err(|_| EvtxError::incomplete_chunk(chunk_number))?;

        if amount_read != EVTX_CHUNK_SIZE {
            return Err(EvtxError::incomplete_chunk(chunk_number));
        }

        // There might be empty chunks in the middle of a dirty file.
        if chunk_data.iter().all(|x| *x == 0) {
            return Ok(None);
        }

        EvtxChunkData::new(chunk_data, validate_checksum)
            .map(Some)
            .map_err(|e| EvtxError::FailedToParseChunk {
                chunk_id: chunk_number,
                source: Box::new(e),
            })
    }

    /// Find the next chunk, staring at `chunk_number` (inclusive).
    /// If a chunk is found, returns the data of the chunk or the relevant error,
    /// and the number of that chunk.
    pub fn find_next_chunk(
        &mut self,
        mut chunk_number: u64,
    ) -> Option<(Result<EvtxChunkData>, u64)> {
        loop {
            match EvtxParser::allocate_chunk(
                &mut self.data,
                chunk_number,
                self.config.validate_checksums,
            ) {
                Err(err) => {
                    // We try to read past the `chunk_count` to allow for dirty files.
                    // But if we failed, it means we really are at the end of the file.
                    if chunk_number >= self.calculated_chunk_count {
                        return None;
                    } else {
                        return Some((Err(err), chunk_number));
                    }
                }
                Ok(None) => {
                    // We try to read past the `chunk_count` to allow for dirty files.
                    // But if we get an empty chunk, we need to keep looking.
                    // Increment and try again.
                    chunk_number = chunk_number.checked_add(1)?
                }
                Ok(Some(chunk)) => {
                    return Some((Ok(chunk), chunk_number));
                }
            };
        }
    }

    /// Return an iterator over all the chunks.
    /// Each chunk supports iterating over it's records in their un-serialized state
    /// (before they are converted to XML or JSON).
    pub fn chunks(&mut self) -> IterChunks<'_, T> {
        self.chunks_from(0)
    }

    /// Return an iterator over chunks starting from the given chunk number.
    pub fn chunks_from(&mut self, start_chunk: u64) -> IterChunks<'_, T> {
        IterChunks {
            parser: self,
            current_chunk_number: start_chunk,
        }
    }

    /// Consumes the parser, returning an iterator over all the chunks.
    /// Each chunk supports iterating over it's records in their un-serialized state
    /// (before they are converted to XML or JSON).
    pub fn into_chunks(self) -> IntoIterChunks<T> {
        self.into_chunks_from(0)
    }

    /// Consumes the parser, returning an iterator over chunks starting from
    /// the given chunk number.
    pub fn into_chunks_from(self, start_chunk: u64) -> IntoIterChunks<T> {
        IntoIterChunks {
            parser: self,
            current_chunk_number: start_chunk,
        }
    }
    /// Return an iterator over all the records.
    /// Records will be mapped `f`, which must produce owned data from the records.
    pub fn serialized_records<'a, U: Send>(
        &'a mut self,
        f: impl FnMut(Result<EvtxRecord<'_>>) -> Result<U> + Send + Sync + Clone + 'a,
    ) -> impl Iterator<Item = Result<U>> + 'a {
        self.serialized_records_from_chunk(0, f)
    }

    fn serialized_records_from_chunk<'a, U: Send>(
        &'a mut self,
        start_chunk: u64,
        f: impl FnMut(Result<EvtxRecord<'_>>) -> Result<U> + Send + Sync + Clone + 'a,
    ) -> impl Iterator<Item = Result<U>> + 'a {
        struct ChunkBatch<U> {
            results: Vec<Result<U>>,
            arena: Bump,
        }

        // Retrieve parser settings here, while `self` is immutably borrowed.
        let num_threads = max(self.config.num_threads, 1);
        let chunk_settings = Arc::clone(&self.config);

        // `self` is mutably borrowed from here on.
        let mut chunks = self.chunks_from(start_chunk);
        let mut arena_pool: Vec<Bump> = (0..num_threads)
            .map(|_| Bump::with_capacity(EVTX_CHUNK_SIZE))
            .collect();

        let records_per_chunk = std::iter::from_fn(move || {
            // Allocate some chunks in advance, so they can be parsed in parallel.
            let mut chunk_of_chunks = Vec::with_capacity(num_threads);

            for _ in 0..num_threads {
                if let Some(chunk) = chunks.next() {
                    let arena = arena_pool.pop().unwrap_or_default();
                    chunk_of_chunks.push((chunk, arena));
                };
            }

            // We only stop once no chunks can be allocated.
            if chunk_of_chunks.is_empty() {
                None
            } else {
                #[cfg(feature = "multithreading")]
                let chunk_iter = chunk_of_chunks.into_par_iter();

                #[cfg(not(feature = "multithreading"))]
                let chunk_iter = chunk_of_chunks.into_iter();

                // Serialize the records in each chunk.
                let iterators: Vec<ChunkBatch<U>> = chunk_iter
                    .enumerate()
                    .map(|(i, (chunk_res, arena))| match chunk_res {
                        Err(err) => ChunkBatch {
                            results: vec![Err(err)],
                            arena,
                        },
                        Ok(mut chunk) => {
                            let chunk_records_res =
                                chunk.parse_with_arena(chunk_settings.clone(), arena);

                            match chunk_records_res {
                                Err(err) => ChunkBatch {
                                    results: vec![Err(EvtxError::FailedToParseChunk {
                                        chunk_id: i as u64,
                                        source: Box::new(err),
                                    })],
                                    arena: Bump::new(),
                                },
                                Ok(mut chunk_records) => {
                                    let results = {
                                        let records = chunk_records.iter();
                                        records.map(f.clone()).collect()
                                    };
                                    let arena = chunk_records.into_arena();
                                    ChunkBatch { results, arena }
                                }
                            }
                        }
                    })
                    .collect();

                let mut flattened = Vec::new();
                for batch in iterators {
                    arena_pool.push(batch.arena);
                    flattened.extend(batch.results);
                }

                Some(flattened.into_iter())
            }
        });

        records_per_chunk.flatten()
    }

    /// Return an iterator over all the records.
    /// Records will be XML-formatted.
    pub fn records(&mut self) -> impl Iterator<Item = Result<SerializedEvtxRecord<String>>> + '_ {
        // '_ is required in the signature because the iterator is bound to &self.
        self.serialized_records(|record| record.and_then(|record| record.into_xml()))
    }

    /// Return an iterator over all the records.
    /// Records will be JSON-formatted.
    pub fn records_json(
        &mut self,
    ) -> impl Iterator<Item = Result<SerializedEvtxRecord<String>>> + '_ {
        self.serialized_records(|record| record.and_then(|record| record.into_json()))
    }

    /// Return an iterator over all the records.
    /// Records will have a `serde_json::Value` data attribute.
    pub fn records_json_value(
        &mut self,
    ) -> impl Iterator<Item = Result<SerializedEvtxRecord<serde_json::Value>>> + '_ {
        self.serialized_records(|record| record.and_then(|record| record.into_json_value()))
    }

    /// Return an iterator over the last `num_records` records, XML-formatted.
    /// Only reads chunk headers to find the starting position, then parses
    /// just the necessary chunks.
    pub fn records_tail(
        &mut self,
        num_records: usize,
    ) -> impl Iterator<Item = Result<SerializedEvtxRecord<String>>> + '_ {
        let (start_chunk, skip) = self.find_tail_start_chunk(num_records);
        self.serialized_records_from_chunk(start_chunk, |record| {
            record.and_then(|record| record.into_xml())
        })
        .skip(skip)
    }

    /// Return an iterator over the last `num_records` records, JSON-formatted.
    /// Only reads chunk headers to find the starting position, then parses
    /// just the necessary chunks.
    pub fn records_json_tail(
        &mut self,
        num_records: usize,
    ) -> impl Iterator<Item = Result<SerializedEvtxRecord<String>>> + '_ {
        let (start_chunk, skip) = self.find_tail_start_chunk(num_records);
        self.serialized_records_from_chunk(start_chunk, |record| {
            record.and_then(|record| record.into_json())
        })
        .skip(skip)
    }

    /// Return an iterator over the last `num_records` records as
    /// `serde_json::Value`.
    /// Only reads chunk headers to find the starting position, then parses
    /// just the necessary chunks.
    pub fn records_json_value_tail(
        &mut self,
        num_records: usize,
    ) -> impl Iterator<Item = Result<SerializedEvtxRecord<serde_json::Value>>> + '_ {
        let (start_chunk, skip) = self.find_tail_start_chunk(num_records);
        self.serialized_records_from_chunk(start_chunk, |record| {
            record.and_then(|record| record.into_json_value())
        })
        .skip(skip)
    }
}

pub struct IterChunks<'c, T: ReadSeek> {
    parser: &'c mut EvtxParser<T>,
    current_chunk_number: u64,
}

impl<T: ReadSeek> Iterator for IterChunks<'_, T> {
    type Item = Result<EvtxChunkData>;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        match self.parser.find_next_chunk(self.current_chunk_number) {
            None => None,
            Some((chunk, chunk_number)) => {
                self.current_chunk_number = chunk_number.checked_add(1)?;

                Some(chunk)
            }
        }
    }
}

pub struct IntoIterChunks<T: ReadSeek> {
    parser: EvtxParser<T>,
    current_chunk_number: u64,
}

impl<T: ReadSeek> Iterator for IntoIterChunks<T> {
    type Item = Result<EvtxChunkData>;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        info!("Chunk {}", self.current_chunk_number);
        match self.parser.find_next_chunk(self.current_chunk_number) {
            None => None,
            Some((chunk, chunk_number)) => {
                self.current_chunk_number = chunk_number.checked_add(1)?;

                Some(chunk)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused_variables)]

    use super::*;
    use crate::ensure_env_logger_initialized;

    fn process_90_records(buffer: &'static [u8]) -> crate::err::Result<()> {
        let mut parser = EvtxParser::from_buffer(buffer.to_vec())?;

        for (i, record) in parser.records().take(90).enumerate() {
            let r = record?;
            assert_eq!(r.event_record_id, i as u64 + 1);
        }

        Ok(())
    }

    // For clion profiler
    #[test]
    fn test_process_single_chunk() -> crate::err::Result<()> {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/security.evtx");
        process_90_records(evtx_file)?;

        Ok(())
    }

    #[test]
    fn test_sample_2() {
        let evtx_file = include_bytes!("../samples/system.evtx");
        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();

        let records: Vec<_> = parser.records().take(10).collect();

        for (i, record) in records.iter().enumerate() {
            match record {
                Ok(r) => {
                    assert_eq!(
                        r.event_record_id,
                        i as u64 + 1,
                        "Parser is skipping records!"
                    );
                }
                Err(e) => panic!("Error while reading record {}, {:?}", i, e),
            }
        }

        // It should be empty, and not a [].
        assert!(
            records[0]
                .as_ref()
                .unwrap()
                .data
                .contains("<Binary></Binary>")
        );
        assert!(
            records[1]
                .as_ref()
                .unwrap()
                .data
                .contains("<Binary>E107070003000C00110010001C00D6000000000000000000</Binary>")
        );
    }

    #[test]
    fn test_parses_first_10_records() {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/security.evtx");
        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();

        for (i, record) in parser.records().take(10).enumerate() {
            match record {
                Ok(r) => {
                    assert_eq!(
                        r.event_record_id,
                        i as u64 + 1,
                        "Parser is skipping records!"
                    );
                }
                Err(e) => panic!("Error while reading record {}, {:?}", i, e),
            }
        }
    }

    #[test]
    fn test_parses_records_from_different_chunks() {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/security.evtx");
        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();

        for (i, record) in parser.records().take(1000).enumerate() {
            match record {
                Ok(r) => {
                    assert_eq!(r.event_record_id, i as u64 + 1);
                }
                Err(e) => println!("Error while reading record {}, {:?}", i, e),
            }
        }
    }

    #[test]
    #[cfg(feature = "multithreading")]
    fn test_multithreading() {
        use std::collections::HashSet;

        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/security.evtx");
        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();

        let mut record_ids = HashSet::new();
        for record in parser.records().take(1000) {
            match record {
                Ok(r) => {
                    record_ids.insert(r.event_record_id);
                }
                Err(e) => panic!("Error while reading record {:?}", e),
            }
        }

        assert_eq!(record_ids.len(), 1000);
    }

    #[test]
    fn test_file_with_only_a_single_chunk() {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/new-user-security.evtx");
        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();

        assert_eq!(parser.records().count(), 4);
    }

    #[test]
    fn test_parses_chunk2() {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/security.evtx");

        let mut chunk = EvtxChunkData::new(
            evtx_file[EVTX_FILE_HEADER_SIZE + EVTX_CHUNK_SIZE
                ..EVTX_FILE_HEADER_SIZE + 2 * EVTX_CHUNK_SIZE]
                .to_vec(),
            false,
        )
        .unwrap();

        assert!(chunk.validate_checksum());

        for record in chunk
            .parse(Arc::new(ParserSettings::default()))
            .unwrap()
            .iter()
        {
            record.unwrap();
        }
    }

    #[test]
    fn test_into_chunks() {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/new-user-security.evtx");
        let parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();

        assert_eq!(parser.into_chunks().count(), 1);
    }

    #[test]
    fn test_into_json_value_records() {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/new-user-security.evtx");
        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();

        let records: Vec<_> = parser.records_json_value().collect();

        for record in records {
            let record = record.unwrap();

            assert!(record.data.is_object());
            assert!(record.data.as_object().unwrap().contains_key("Event"));
        }
    }

    #[test]
    fn test_records_tail_returns_last_n_records() {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/security.evtx");

        // Get all records to compare against
        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();
        let all_records: Vec<_> = parser
            .records()
            .filter_map(|r| r.ok())
            .collect();
        let total = all_records.len();
        assert!(total > 100, "Need enough records for the test");

        // Get last 100 via tail
        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();
        let tail_records: Vec<_> = parser
            .records_tail(100)
            .filter_map(|r| r.ok())
            .collect();

        assert_eq!(tail_records.len(), 100);

        // Verify they match the last 100 from the full parse
        let expected = &all_records[total - 100..];
        for (tail_rec, expected_rec) in tail_records.iter().zip(expected.iter()) {
            assert_eq!(tail_rec.event_record_id, expected_rec.event_record_id);
            assert_eq!(tail_rec.data, expected_rec.data);
        }
    }

    #[test]
    fn test_records_tail_more_than_total_returns_all() {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/security.evtx");

        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();
        let all_count = parser.records().filter_map(|r| r.ok()).count();

        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();
        let tail_count = parser.records_tail(999999).filter_map(|r| r.ok()).count();

        assert_eq!(tail_count, all_count);
    }

    #[test]
    fn test_records_json_tail() {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/security.evtx");

        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();
        let tail_records: Vec<_> = parser
            .records_json_tail(10)
            .filter_map(|r| r.ok())
            .collect();

        assert_eq!(tail_records.len(), 10);
        // Verify JSON is valid
        for rec in &tail_records {
            assert!(serde_json::from_str::<serde_json::Value>(&rec.data).is_ok());
        }
    }

    #[test]
    fn test_records_tail_single_chunk_file() {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/new-user-security.evtx");

        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();
        let tail_records: Vec<_> = parser
            .records_tail(2)
            .filter_map(|r| r.ok())
            .collect();

        assert_eq!(tail_records.len(), 2);

        // Verify these are the last 2 records
        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();
        let all_records: Vec<_> = parser
            .records()
            .filter_map(|r| r.ok())
            .collect();
        let total = all_records.len();

        assert_eq!(
            tail_records.last().unwrap().event_record_id,
            all_records.last().unwrap().event_record_id
        );
        assert_eq!(
            tail_records.first().unwrap().event_record_id,
            all_records[total - 2].event_record_id
        );
    }

    #[test]
    fn test_chunk_count_accessor() {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/security.evtx");
        let parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();

        // The header stores chunk_count as u16 (26), but the calculated
        // count from file size may differ for files with trailing data.
        assert!(parser.chunk_count() > 0);
    }

    #[test]
    fn test_parse_event_with_zero_() {
        ensure_env_logger_initialized();
        let evtx_file = include_bytes!("../samples/new-user-security.evtx");
        let mut parser = EvtxParser::from_buffer(evtx_file.to_vec()).unwrap();

        let records: Vec<_> = parser.records_json_value().collect();

        for record in records {
            let record = record.unwrap();

            assert!(record.data.is_object());
            assert!(record.data.as_object().unwrap().contains_key("Event"));
        }
    }
}
