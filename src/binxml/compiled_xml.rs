//! Compiled XML templates for fast per-record rendering.
//!
//! Instead of building a full IR tree per record (clone + resolve + walk), this module
//! pre-compiles each BinXml template into static XML byte fragments interleaved with
//! substitution slots. Per-record rendering becomes: write `parts[0]`, format
//! `value[slots[0].sub_id]`, write `parts[1]`, ... — no tree building, no tree walking.
//!
//! Handles TemplateInstance records, inline BinXml records (forwarded events),
//! inner BinXmlType fragments (both TemplateInstance-wrapped and inline token streams),
//! array expansion, processing instructions, and multi-token attribute values.

use crate::ParserSettings;
use crate::binxml::name::BinXmlNameRef;
use crate::binxml::value_render::ValueRenderer;
use crate::binxml::value_variant::BinXmlValue;
use crate::evtx_chunk::EvtxChunk;
use crate::model::ir::is_optional_empty;
use crate::string_cache::StringCache;
use crate::utils::ByteCursor;
use encoding::EncodingRef;

/// A substitution slot in a compiled XML template.
struct SubSlot {
    /// Index into the record's substitution value array.
    sub_id: u16,
    /// True if this substitution is optional (type 0x0e).
    optional: bool,
    /// True if this slot appears in an attribute context.
    in_attribute: bool,
    /// Bytes to emit before the formatted value (e.g. ` Name="` for attributes).
    /// Empty if the value appears as element text content with no prefix needed.
    attr_prefix: Vec<u8>,
    /// Bytes to emit after the formatted value (e.g. `"` to close an attribute).
    /// Empty if no suffix needed.
    attr_suffix: Vec<u8>,
    /// Indent level at this slot (number of spaces). Used to offset inner BinXml fragments.
    indent_level: usize,
    /// For element text slots: byte offset in the preceding static part where the
    /// containing element's opening tag starts (including indent/newline).
    /// Used for array expansion to repeat the element.
    repeat_prefix_start: usize,
    /// Length of the containing element's name. Used to construct the close tag
    /// during array expansion. 0 if not applicable.
    element_name_len: u8,
}

/// A compiled XML template — static XML parts interleaved with substitution slots.
pub(crate) struct CompiledXmlTemplate {
    /// N+1 static XML byte fragments for N slots.
    pub(crate) parts: Vec<Vec<u8>>,
    /// Substitution slot metadata.
    slots: Vec<SubSlot>,
}

/// Error type used internally during compilation to signal bail conditions.
enum CompileError {
    /// The template cannot be compiled (e.g. nested templates, unsupported tokens).
    Bail,
}

/// Attempt to compile a BinXml template definition into a `CompiledXmlTemplate`.
///
/// Returns `None` if the template cannot be compiled (bail conditions met).
pub(crate) fn compile_xml_template(
    chunk: &EvtxChunk<'_>,
    template_def_offset: u32,
    settings: &ParserSettings,
) -> Option<CompiledXmlTemplate> {
    match compile_xml_template_inner(chunk, template_def_offset, settings) {
        Ok(compiled) => Some(compiled),
        Err(CompileError::Bail) => None,
    }
}

fn compile_xml_template_inner(
    chunk: &EvtxChunk<'_>,
    template_def_offset: u32,
    settings: &ParserSettings,
) -> std::result::Result<CompiledXmlTemplate, CompileError> {
    let data = chunk.data;

    // Read template definition header: next_offset(4) + guid(16) + data_size(4) = 24 bytes
    let header_start = template_def_offset as usize;
    if header_start + 24 > data.len() {
        return Err(CompileError::Bail);
    }
    // Skip next_template_offset (4) and guid (16)
    let data_size_offset = header_start + 20;
    let data_size = u32::from_le_bytes([
        data[data_size_offset],
        data[data_size_offset + 1],
        data[data_size_offset + 2],
        data[data_size_offset + 3],
    ]);

    let data_start = header_start + 24;
    let data_end = data_start + data_size as usize;
    if data_end > data.len() {
        return Err(CompileError::Bail);
    }

    let indent = settings.should_indent();
    let ansi_codec = settings.get_ansi_codec();
    let mut compiler = TemplateCompiler::new(chunk, ansi_codec, indent, true);
    compiler.compile_bytes(data_start, data_end)?;
    Ok(compiler.finish())
}

/// Stateful compiler that walks template BinXml bytes and builds the compiled template.
struct TemplateCompiler<'a> {
    data: &'a [u8],
    chunk: &'a EvtxChunk<'a>,
    string_cache: &'a StringCache,
    ansi_codec: EncodingRef,
    indent: bool,
    /// True if OpenStartElement tokens include a dependency identifier (u16).
    /// Template definitions have this; inline BinXml fragments (type 0x21 values) do not.
    has_dependency_identifier: bool,
    /// Current accumulating static XML bytes (the "current part").
    current_part: Vec<u8>,
    /// Completed parts so far.
    parts: Vec<Vec<u8>>,
    /// Slots collected so far.
    slots: Vec<SubSlot>,
    /// Element stack for indentation tracking.
    /// Each entry is (element_name_str, has_children_flag).
    element_stack: Vec<StackEntry>,
    /// True if we are currently inside an attribute value.
    in_attribute: bool,
    /// Pending attribute name prefix (` AttrName="`) to emit only if the value is non-empty.
    /// For substitution slots in attributes, we defer the prefix to the slot.
    pending_attr_prefix: Option<Vec<u8>>,
}

struct StackEntry {
    name: String,
    indent_level: usize,
    has_element_child: bool,
    has_any_child: bool,
    children_started: bool,
    /// Byte offset in `current_part` where this element's opening tag starts
    /// (including indent/newline prefix). Used for array expansion.
    open_byte_start: usize,
}

impl<'a> TemplateCompiler<'a> {
    fn new(chunk: &'a EvtxChunk<'a>, ansi_codec: EncodingRef, indent: bool, has_dependency_identifier: bool) -> Self {
        TemplateCompiler {
            data: chunk.data,
            chunk,
            string_cache: &chunk.string_cache,
            ansi_codec,
            indent,
            has_dependency_identifier,
            current_part: Vec::with_capacity(512),
            parts: Vec::new(),
            slots: Vec::new(),
            element_stack: Vec::new(),
            in_attribute: false,
            pending_attr_prefix: None,
        }
    }

    fn compile_bytes(
        &mut self,
        data_start: usize,
        data_end: usize,
    ) -> std::result::Result<(), CompileError> {
        let mut cursor = ByteCursor::with_pos(self.data, data_start).map_err(|_| CompileError::Bail)?;
        let data_size = (data_end - data_start) as u32;
        let mut data_read: u32 = 0;
        let mut eof = false;

        while !eof && data_read < data_size {
            let start = cursor.position();
            let token_byte = cursor.u8().map_err(|_| CompileError::Bail)?;

            match token_byte {
                0x00 => {
                    eof = true;
                }
                0x0c => {
                    // Nested TemplateInstance — bail
                    return Err(CompileError::Bail);
                }
                0x0f => {
                    // FragmentHeader — skip 3 bytes (major, minor, flags)
                    let _ = cursor.u8().map_err(|_| CompileError::Bail)?;
                    let _ = cursor.u8().map_err(|_| CompileError::Bail)?;
                    let _ = cursor.u8().map_err(|_| CompileError::Bail)?;
                }
                0x01 => {
                    // OpenStartElement (no attributes)
                    self.handle_open_start_element(&mut cursor, false)?;
                }
                0x41 => {
                    // OpenStartElement (has attributes)
                    self.handle_open_start_element(&mut cursor, true)?;
                }
                0x02 => {
                    // CloseStartElement — finalize element start tag
                    self.handle_close_start_element()?;
                }
                0x03 => {
                    // CloseEmptyElement — self-closing element
                    self.handle_close_empty_element()?;
                }
                0x04 => {
                    // CloseElement — write closing tag
                    self.handle_close_element()?;
                }
                0x06 | 0x46 => {
                    // Attribute
                    self.handle_attribute(&mut cursor)?;
                }
                0x05 | 0x45 => {
                    // Value — inline text value in template definition (rare but possible)
                    self.handle_value(&mut cursor)?;
                }
                0x09 | 0x49 => {
                    // EntityReference
                    self.handle_entity_ref(&mut cursor)?;
                }
                0x0d => {
                    // NormalSubstitution
                    self.handle_substitution(&mut cursor, false)?;
                }
                0x0e => {
                    // OptionalSubstitution
                    self.handle_substitution(&mut cursor, true)?;
                }
                0x0a => {
                    // ProcessingInstructionTarget
                    self.handle_pi_target(&mut cursor)?;
                }
                0x0b => {
                    // ProcessingInstructionData
                    self.handle_pi_data(&mut cursor)?;
                }
                0x07 | 0x47 => {
                    // CDataSection — bail
                    return Err(CompileError::Bail);
                }
                0x08 | 0x48 => {
                    // CharReference — bail
                    return Err(CompileError::Bail);
                }
                _ => {
                    return Err(CompileError::Bail);
                }
            }

            let total_read = cursor.position() - start;
            data_read = data_read.saturating_add(total_read as u32);
        }

        Ok(())
    }

    fn handle_open_start_element(
        &mut self,
        cursor: &mut ByteCursor<'a>,
        has_attributes: bool,
    ) -> std::result::Result<(), CompileError> {
        // Template definitions include a dependency identifier (u16);
        // inline BinXml fragments (type 0x21 values) omit it.
        if self.has_dependency_identifier {
            let _ = cursor.u16().map_err(|_| CompileError::Bail)?;
        }
        // data_size (u32)
        let _ = cursor.u32().map_err(|_| CompileError::Bail)?;
        // name ref
        let name_ref = BinXmlNameRef::from_cursor(cursor).map_err(|_| CompileError::Bail)?;
        // attribute list data size (u32) if has_attributes
        if has_attributes {
            let _ = cursor.u32().map_err(|_| CompileError::Bail)?;
        }

        let name_str = self.resolve_name(&name_ref)?;
        let indent_level = self.current_indent_level();

        // Mark parent as having an element child
        if let Some(parent) = self.element_stack.last_mut() {
            if !parent.children_started {
                // First child of parent — write newline after parent's ">"
                if self.indent {
                    self.current_part.push(b'\n');
                }
                parent.children_started = true;
            }
            parent.has_element_child = true;
            parent.has_any_child = true;
        }

        // Record where this element's opening tag begins (including indent)
        let open_byte_start = self.current_part.len();

        // Write indentation
        self.write_indent(indent_level);

        // Write `<Name`
        self.current_part.push(b'<');
        self.current_part.extend_from_slice(name_str.as_bytes());

        self.element_stack.push(StackEntry {
            name: name_str,
            indent_level,
            has_element_child: false,
            has_any_child: false,
            children_started: false,
            open_byte_start,
        });

        Ok(())
    }

    fn handle_attribute(
        &mut self,
        cursor: &mut ByteCursor<'a>,
    ) -> std::result::Result<(), CompileError> {
        // Close any previous attribute that's still open.
        self.close_attribute_if_open();

        let name_ref = BinXmlNameRef::from_cursor(cursor).map_err(|_| CompileError::Bail)?;
        let name = self.resolve_name(&name_ref)?;

        // We accumulate the attribute prefix (` Name="`) as pending.
        // If the next token is a substitution, the prefix goes into the slot.
        // Otherwise it goes into current_part directly.
        let mut prefix = Vec::with_capacity(name.len() + 3);
        prefix.push(b' ');
        prefix.extend_from_slice(name.as_bytes());
        prefix.extend_from_slice(b"=\"");
        self.pending_attr_prefix = Some(prefix);
        self.in_attribute = true;

        Ok(())
    }

    fn handle_close_start_element(&mut self) -> std::result::Result<(), CompileError> {
        // Close any open attribute value with its closing quote.
        self.close_attribute_if_open();

        // Write `>`
        self.current_part.push(b'>');

        Ok(())
    }

    fn handle_close_empty_element(&mut self) -> std::result::Result<(), CompileError> {
        self.close_attribute_if_open();

        // Pop the element from stack — it was pushed at open_start
        let entry = self.element_stack.pop().ok_or(CompileError::Bail)?;

        // Write `>` then close tag on same/next line (matching ir_xml behavior)
        // For empty elements, ir_xml writes:
        //   <Tag>\n  </Tag>\n    (for most tags)
        //   <Tag></Tag>\n        (for Binary)
        self.current_part.push(b'>');

        if entry.name == "Binary" {
            self.current_part.extend_from_slice(b"</");
            self.current_part.extend_from_slice(entry.name.as_bytes());
            self.current_part.push(b'>');
            if self.indent {
                self.current_part.push(b'\n');
            }
        } else {
            if self.indent {
                self.current_part.push(b'\n');
            }
            self.write_indent(entry.indent_level);
            self.current_part.extend_from_slice(b"</");
            self.current_part.extend_from_slice(entry.name.as_bytes());
            self.current_part.push(b'>');
            if self.indent {
                self.current_part.push(b'\n');
            }
        }

        Ok(())
    }

    fn handle_close_element(&mut self) -> std::result::Result<(), CompileError> {
        let entry = self.element_stack.pop().ok_or(CompileError::Bail)?;

        if entry.has_element_child {
            // Children were on separate lines — write indent + close tag
            self.write_indent(entry.indent_level);
        } else if !entry.has_any_child && self.indent && entry.name != "Binary" {
            // Empty element using CloseElement (not CloseEmptyElement).
            // Match IR renderer: `>\n  </Tag>\n`
            // Binary is exempted — it renders inline: `<Binary></Binary>`
            self.current_part.push(b'\n');
            self.write_indent(entry.indent_level);
        }
        // Otherwise: text-only children — close tag follows inline.

        self.current_part.extend_from_slice(b"</");
        self.current_part.extend_from_slice(entry.name.as_bytes());
        self.current_part.push(b'>');
        if self.indent {
            self.current_part.push(b'\n');
        }

        Ok(())
    }

    fn handle_entity_ref(
        &mut self,
        cursor: &mut ByteCursor<'a>,
    ) -> std::result::Result<(), CompileError> {
        let name_ref = BinXmlNameRef::from_cursor(cursor).map_err(|_| CompileError::Bail)?;
        let name = self.resolve_name(&name_ref)?;

        // In attribute context, just emit the pending prefix (without closing quote).
        // The entity ref is part of the attribute value.
        if self.in_attribute {
            if let Some(prefix) = self.pending_attr_prefix.take() {
                self.current_part.extend_from_slice(&prefix);
            }
        } else {
            self.flush_pending_attr_prefix();
        }

        // Mark parent as having child content (for element context)
        if !self.in_attribute {
            if let Some(parent) = self.element_stack.last_mut() {
                parent.has_any_child = true;
            }
        }

        self.current_part.push(b'&');
        self.current_part.extend_from_slice(name.as_bytes());
        self.current_part.push(b';');

        Ok(())
    }

    fn handle_pi_target(
        &mut self,
        cursor: &mut ByteCursor<'a>,
    ) -> std::result::Result<(), CompileError> {
        let name_ref = BinXmlNameRef::from_cursor(cursor).map_err(|_| CompileError::Bail)?;
        let name = self.resolve_name(&name_ref)?;

        // Mark parent as having child content
        if let Some(parent) = self.element_stack.last_mut() {
            parent.has_any_child = true;
        }

        self.current_part.extend_from_slice(b"<?");
        self.current_part.extend_from_slice(name.as_bytes());

        Ok(())
    }

    fn handle_pi_data(
        &mut self,
        cursor: &mut ByteCursor<'a>,
    ) -> std::result::Result<(), CompileError> {
        // Read length-prefixed UTF-16LE string, convert to UTF-8
        let data = cursor.len_prefixed_utf16_string_utf8(false, "pi_data")
            .map_err(|_| CompileError::Bail)?
            .unwrap_or_default();

        if !data.is_empty() {
            self.current_part.push(b' ');
            self.current_part.extend_from_slice(data.as_bytes());
        }
        self.current_part.extend_from_slice(b"?>");

        Ok(())
    }

    fn handle_value(
        &mut self,
        cursor: &mut ByteCursor<'a>,
    ) -> std::result::Result<(), CompileError> {
        // Inline values in template definitions — parse the value and render it as static XML.
        let in_attr = self.in_attribute;
        let value = BinXmlValue::from_binxml_cursor_in(
            cursor,
            Some(self.chunk),
            None,
            self.ansi_codec,
            &self.chunk.arena,
        )
        .map_err(|_| CompileError::Bail)?;

        if in_attr {
            // Attribute context: emit prefix (if pending), then render value.
            // Do NOT close the attribute quote here — the attribute value may be a
            // sequence of Value/EntityRef/CharRef tokens. The closing `"` is handled
            // when the attribute ends (at CloseStartElement, CloseEmptyElement, or
            // the next Attribute token).
            if is_optional_empty(&value) {
                // Empty value in attribute — skip (don't emit prefix).
                // The attribute close is handled by flush_pending_attr_prefix later.
            } else {
                if let Some(prefix) = self.pending_attr_prefix.take() {
                    self.current_part.extend_from_slice(&prefix);
                }
                let mut renderer = ValueRenderer::new();
                renderer
                    .write_xml_value_text(&mut self.current_part, &value, true)
                    .map_err(|_| CompileError::Bail)?;
            }
        } else {
            self.flush_pending_attr_prefix();

            // Mark parent as having child content
            if let Some(parent) = self.element_stack.last_mut() {
                parent.has_any_child = true;
            }

            // Render the value directly into the static part buffer
            let mut renderer = ValueRenderer::new();
            renderer
                .write_xml_value_text(&mut self.current_part, &value, false)
                .map_err(|_| CompileError::Bail)?;
        }

        Ok(())
    }

    fn handle_substitution(
        &mut self,
        cursor: &mut ByteCursor<'a>,
        optional: bool,
    ) -> std::result::Result<(), CompileError> {
        let sub_index = cursor.u16().map_err(|_| CompileError::Bail)?;
        let _value_type = cursor.u8().map_err(|_| CompileError::Bail)?;

        if self.in_attribute {
            // Attribute context: the pending_attr_prefix becomes the slot's prefix,
            // and `"` becomes the slot's suffix. The attribute is only emitted if the
            // value is non-empty (for optional subs).
            let attr_prefix = self.pending_attr_prefix.take().unwrap_or_default();
            let attr_suffix = b"\"".to_vec();

            // End current part, create slot
            let finished_part = std::mem::replace(&mut self.current_part, Vec::with_capacity(256));
            self.parts.push(finished_part);
            let indent_level = self.current_indent_level();
            self.slots.push(SubSlot {
                sub_id: sub_index,
                optional,
                in_attribute: true,
                attr_prefix,
                attr_suffix,
                indent_level,
                repeat_prefix_start: 0,
                element_name_len: 0,
            });

            // The attribute is now "consumed" — the close quote is in the slot suffix
            self.in_attribute = false;
        } else {
            // Element text context
            self.flush_pending_attr_prefix();

            // Mark parent as having child content
            if let Some(parent) = self.element_stack.last_mut() {
                parent.has_any_child = true;
            }

            // Record element repeat info for array expansion.
            let (repeat_prefix_start, element_name_len) =
                if let Some(entry) = self.element_stack.last() {
                    (entry.open_byte_start, entry.name.len().min(255) as u8)
                } else {
                    (0, 0)
                };

            let indent_level = self.current_indent_level();
            let finished_part = std::mem::replace(&mut self.current_part, Vec::with_capacity(256));
            self.parts.push(finished_part);
            self.slots.push(SubSlot {
                sub_id: sub_index,
                optional,
                in_attribute: false,
                attr_prefix: Vec::new(),
                attr_suffix: Vec::new(),
                indent_level,
                repeat_prefix_start,
                element_name_len,
            });
        }

        Ok(())
    }

    /// Close an open attribute: flush any pending prefix (empty attribute) or
    /// just add the closing `"` if content was already written.
    fn close_attribute_if_open(&mut self) {
        if self.in_attribute {
            if let Some(prefix) = self.pending_attr_prefix.take() {
                // No content was written for this attribute — emit prefix + closing quote.
                self.current_part.extend_from_slice(&prefix);
            }
            self.current_part.push(b'"');
            self.in_attribute = false;
        }
    }

    fn flush_pending_attr_prefix(&mut self) {
        if let Some(prefix) = self.pending_attr_prefix.take() {
            self.current_part.extend_from_slice(&prefix);
            // Close the attribute value quote
            self.current_part.push(b'"');
            self.in_attribute = false;
        }
    }

    fn resolve_name(&self, name_ref: &BinXmlNameRef) -> std::result::Result<String, CompileError> {
        if let Some(s) = self.string_cache.get_cached_string(name_ref.offset) {
            return Ok(s.as_str().to_string());
        }
        // Fail-soft fallback: read the name directly from chunk data.
        // The name starts 6 bytes after the offset (past the BinXmlNameLink).
        let name_off = name_ref.offset.checked_add(6)
            .ok_or(CompileError::Bail)?;
        let mut cursor = ByteCursor::with_pos(self.data, name_off as usize)
            .map_err(|_| CompileError::Bail)?;
        cursor.len_prefixed_utf16_string_utf8(true, "name")
            .map_err(|_| CompileError::Bail)?
            .ok_or(CompileError::Bail)
    }

    fn current_indent_level(&self) -> usize {
        self.element_stack.len() * 2
    }

    fn write_indent(&mut self, level: usize) {
        if !self.indent {
            return;
        }
        for _ in 0..level {
            self.current_part.push(b' ');
        }
    }

    fn finish(mut self) -> CompiledXmlTemplate {
        // Push the final part
        self.parts.push(self.current_part);
        CompiledXmlTemplate {
            parts: self.parts,
            slots: self.slots,
        }
    }
}

/// Write a static template part to the buffer, inserting `indent_offset` spaces after
/// each `\n` that is followed by more content (not at the very end).
fn write_part_with_indent(buf: &mut Vec<u8>, part: &[u8], indent_offset: usize) {
    if indent_offset == 0 || part.is_empty() {
        buf.extend_from_slice(part);
        return;
    }
    for (pos, &byte) in part.iter().enumerate() {
        buf.push(byte);
        if byte == b'\n' && pos + 1 < part.len() {
            for _ in 0..indent_offset {
                buf.push(b' ');
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Raw value rendering — format substitution values directly from chunk bytes
// without constructing intermediate BinXmlValue enums.
// ---------------------------------------------------------------------------

use crate::binxml::tokens::RawSubValue;
use sonic_rs::format::{CompactFormatter, Formatter};

/// Context for raw rendering, needed for recursive BinXmlType fragment handling.
pub(crate) struct RawRenderContext<'a, 'c> {
    pub chunk: &'a EvtxChunk<'a>,
    pub cache: &'c mut crate::binxml::ir::IrTemplateCache<'a>,
    pub settings: &'c ParserSettings,
}

/// Render a compiled XML template using raw (unparsed) substitution descriptors.
///
/// Same structure as `render_compiled_xml` but reads value bytes directly from
/// `chunk_data` via `RawSubValue` offsets instead of pre-parsed `BinXmlValue` enums.
///
/// Returns `true` on success, `false` if a bail condition is encountered
/// (EvtHandle, EvtXml) — the caller should report an error.
pub(crate) fn render_compiled_xml_raw(
    template: &CompiledXmlTemplate,
    raw_values: &[RawSubValue],
    chunk_data: &[u8],
    buf: &mut Vec<u8>,
    ctx: &mut RawRenderContext<'_, '_>,
    indent: bool,
    indent_offset: usize,
) -> bool {
    let mut float_buf = zmij::Buffer::new();
    let mut fmt = CompactFormatter;

    // After rendering a BinXmlType value, the close tag of the parent element
    // needs indentation. Track this across iterations.
    let mut binxml_close_indent: Option<usize> = None;

    // After array expansion, skip this many bytes at the start of the next static part
    // (the original close tag that was replaced by the repeated element close tags).
    let mut skip_next_part_prefix: usize = 0;

    for (i, slot) in template.slots.iter().enumerate() {
        // If previous slot was BinXmlType, add indent before the close tag
        if let Some(amt) = binxml_close_indent.take() {
            for _ in 0..amt {
                buf.push(b' ');
            }
        }

        // Write static part before this slot (skipping bytes consumed by previous array expansion)
        let part = &template.parts[i];
        let skip = skip_next_part_prefix.min(part.len());
        skip_next_part_prefix = 0;
        write_part_with_indent(buf, &part[skip..], indent_offset);

        let rv = match raw_values.get(slot.sub_id as usize) {
            Some(rv) => rv,
            None => {
                // Missing substitution — treat as empty optional
                handle_raw_optional_empty(template, buf, slot, i, indent, indent_offset);
                continue;
            }
        };

        // Bail on types we can't render from raw bytes.
        match rv.value_type {
            0x20 | 0x23 => return false,
            _ => {}
        }

        // Bounds check and extract raw bytes early so we can check actual content.
        let end = rv.offset + rv.size as usize;
        if end > chunk_data.len() {
            return false;
        }
        let raw = &chunk_data[rv.offset..end];

        // Content-aware empty check: NullType is always empty; strings check
        // for NUL-only content (matching the IR parser's trimming behavior).
        // For array types, use the original type (non-empty raw = non-empty value),
        // matching the IR path where StringArrayType is never considered empty.
        let is_empty = !raw_value_has_content(raw, rv.value_type);

        // For optional empty substitutions in indented mode, add `\n` + indent
        // before the close tag to match the IR renderer's empty element formatting.
        // For non-optional empty, just skip (close tag follows inline).
        if slot.optional && is_empty {
            handle_raw_optional_empty(template, buf, slot, i, indent, indent_offset);
            continue;
        }
        if is_empty {
            continue;
        }

        // Handle BinXmlType (0x21) — recursively compile and render inner fragment
        if rv.value_type == 0x21 {
            // BinXmlType expands to element children. Add `\n` before the
            // inner content if the preceding static part didn't end with one.
            if indent && !slot.in_attribute && !template.parts[i].ends_with(b"\n") {
                buf.push(b'\n');
            }

            let fragment_indent = if indent { indent_offset + slot.indent_level } else { 0 };
            if !render_binxml_fragment_raw(raw, buf, ctx, fragment_indent) {
                return false;
            }

            // After the fragment, the close tag in the next static part needs indent.
            if indent && !slot.in_attribute {
                binxml_close_indent =
                    Some(indent_offset + slot.indent_level.saturating_sub(2));
            }
            continue;
        }

        // Handle array types (0x80+) — element repetition per MS-EVEN6 §3.1.4.7.5
        if rv.value_type >= 0x80 {
            let base_type = rv.value_type & 0x7F;
            let items = split_array_items(raw, base_type);

            if items.len() <= 1 {
                // Single-item array: render as scalar value
                if let Some(&item) = items.first() {
                    if !write_raw_value(buf, item, base_type, item.len() as u16, slot.in_attribute, &mut float_buf, &mut fmt) {
                        return false;
                    }
                }
                continue;
            }

            // Multi-item array: repeat the containing element for each item.
            // The element opening tag is at the end of parts[i].
            let raw_opening = &part[slot.repeat_prefix_start..];

            // Undo the element opening that was written as part of parts[i].
            // Since raw_opening has no internal \n, rendered length == raw length.
            buf.truncate(buf.len() - raw_opening.len());

            // Render each item as a repeated element
            for (j, &item) in items.iter().enumerate() {
                if j > 0 {
                    if indent {
                        buf.push(b'\n');
                        for _ in 0..indent_offset {
                            buf.push(b' ');
                        }
                    }
                }
                buf.extend_from_slice(raw_opening);

                let name_bytes = extract_element_name(raw_opening);
                let item_has_content = raw_value_has_content(item, base_type);

                if item_has_content {
                    if !write_raw_value(buf, item, base_type, item.len() as u16, slot.in_attribute, &mut float_buf, &mut fmt) {
                        return false;
                    }
                } else if indent {
                    // Empty item: IR path uses Omit which produces empty element
                    // formatting with \n + indent before the close tag.
                    buf.push(b'\n');
                    let close_indent = indent_offset + slot.indent_level.saturating_sub(2);
                    for _ in 0..close_indent {
                        buf.push(b' ');
                    }
                }

                // Write close tag </Name>
                buf.extend_from_slice(b"</");
                buf.extend_from_slice(name_bytes);
                buf.push(b'>');
            }

            // Write \n + indent_offset after last element (replaces the skipped \n in parts[i+1])
            if indent {
                buf.push(b'\n');
                for _ in 0..indent_offset {
                    buf.push(b' ');
                }
            }

            // Skip the original close tag + \n in parts[i+1]
            let name_len = slot.element_name_len as usize;
            skip_next_part_prefix = 2 + name_len + 1 + if indent { 1 } else { 0 }; // </Name>\n
            continue;
        }

        // Write prefix (attribute opening like ` Name="`)
        if !slot.attr_prefix.is_empty() {
            buf.extend_from_slice(&slot.attr_prefix);
        }

        // Format the value from raw bytes
        let ok = write_raw_value(
            buf,
            raw,
            rv.value_type,
            rv.size,
            slot.in_attribute,
            &mut float_buf,
            &mut fmt,
        );
        if !ok {
            return false;
        }

        // Write suffix (attribute closing like `"`)
        if !slot.attr_suffix.is_empty() {
            buf.extend_from_slice(&slot.attr_suffix);
        }
    }

    // Write the final static part
    if let Some(amt) = binxml_close_indent.take() {
        for _ in 0..amt {
            buf.push(b' ');
        }
    }
    if let Some(last_part) = template.parts.last() {
        let skip = skip_next_part_prefix.min(last_part.len());
        write_part_with_indent(buf, &last_part[skip..], indent_offset);
    }

    true
}

/// Render an embedded BinXml fragment using the raw path.
///
/// The fragment bytes are the inner BinXml content from a BinXmlType substitution.
/// Returns `true` on success, `false` on bail.
fn render_binxml_fragment_raw(
    inner_bytes: &[u8],
    buf: &mut Vec<u8>,
    ctx: &mut RawRenderContext<'_, '_>,
    indent_offset: usize,
) -> bool {
    // Determine offset of the TemplateInstance (0x0c) token.
    // Fragments may start with FragmentHeader(0x0f) + 3 bytes + 0x0c,
    // or directly with bare 0x0c (no FragmentHeader wrapper).
    let template_token_offset = if inner_bytes.len() >= 5
        && inner_bytes[0] == 0x0f
        && inner_bytes[4] == 0x0c
    {
        4
    } else if !inner_bytes.is_empty() && inner_bytes[0] == 0x0c {
        0
    } else {
        // Neither FragmentHeader+TemplateInstance nor bare TemplateInstance.
        // This is a raw BinXml token stream (e.g. inline elements, PI targets).
        return render_binxml_inline_tokens(inner_bytes, buf, ctx, indent_offset);
    };

    // Compute absolute offset of inner_bytes within chunk data
    let inner_abs_offset = {
        let data_start = ctx.chunk.data.as_ptr() as usize;
        let inner_start = inner_bytes.as_ptr() as usize;
        inner_start - data_start
    };

    // Cursor positioned after the 0x0c token byte
    let mut cursor = match ByteCursor::with_pos(ctx.chunk.data, inner_abs_offset + template_token_offset + 1) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Read raw value descriptors for the inner template
    let mut inner_raw_values = Vec::with_capacity(16);
    let template_def_offset = match crate::binxml::tokens::read_template_raw_values(
        &mut cursor,
        &mut inner_raw_values,
    ) {
        Ok(off) => off,
        Err(_) => return false,
    };

    // Look up or compile the inner template
    let compiled = match ctx.cache.get_or_compile_xml_template(
        ctx.chunk,
        template_def_offset,
        ctx.settings,
    ) {
        Some(c) => c,
        None => return false,
    };

    let indent = ctx.settings.should_indent();

    // Add indent at the start of the fragment (first line)
    for _ in 0..indent_offset {
        buf.push(b' ');
    }

    // Render recursively
    let ok = render_compiled_xml_raw(
        &compiled,
        &inner_raw_values,
        ctx.chunk.data,
        buf,
        ctx,
        indent,
        indent_offset,
    );
    ok
}

/// Render a record whose BinXml content is not wrapped in a TemplateInstance.
///
/// Some EVTX files (notably forwarded events) have records where the FragmentHeader
/// is followed directly by OpenStartElement tokens instead of a TemplateInstance.
/// These records contain fully-expanded BinXml with no substitution slots.
pub(crate) fn render_record_inline_tokens<'a>(
    inner_bytes: &[u8],
    buf: &mut Vec<u8>,
    chunk: &'a EvtxChunk<'a>,
    _ir_cache: &mut crate::binxml::ir::IrTemplateCache<'a>,
    settings: &ParserSettings,
) -> bool {
    let inner_abs_offset = {
        let data_start = chunk.data.as_ptr() as usize;
        let inner_start = inner_bytes.as_ptr() as usize;
        inner_start - data_start
    };

    let data_start = inner_abs_offset;
    let data_end = inner_abs_offset + inner_bytes.len();

    let indent = settings.should_indent();
    let ansi_codec = settings.get_ansi_codec();
    let mut compiler = TemplateCompiler::new(chunk, ansi_codec, indent, false);
    if let Err(_) = compiler.compile_bytes(data_start, data_end) {
        return false;
    }
    let compiled = compiler.finish();

    if compiled.slots.is_empty() {
        // No substitution slots — write static parts directly.
        for part in &compiled.parts {
            buf.extend_from_slice(part);
        }
        return true;
    }

    // Has substitution slots — these inline records may contain nested TemplateInstances.
    // Fall back to false (caller should use IR path).
    false
}

/// Render an inline BinXml token stream (not wrapped in a TemplateInstance).
///
/// These are self-contained BinXml fragments stored as BinXmlType substitution
/// values, containing raw tokens like OpenStartElement, Attributes, PI targets, etc.
/// They have no substitution slots — the XML is fully expanded.
fn render_binxml_inline_tokens(
    inner_bytes: &[u8],
    buf: &mut Vec<u8>,
    ctx: &mut RawRenderContext<'_, '_>,
    indent_offset: usize,
) -> bool {
    let inner_abs_offset = {
        let data_start = ctx.chunk.data.as_ptr() as usize;
        let inner_start = inner_bytes.as_ptr() as usize;
        inner_start - data_start
    };

    let data_start = inner_abs_offset;
    let data_end = inner_abs_offset + inner_bytes.len();

    let indent = ctx.settings.should_indent();
    let ansi_codec = ctx.settings.get_ansi_codec();
    let mut compiler = TemplateCompiler::new(ctx.chunk, ansi_codec, indent, false);
    if compiler.compile_bytes(data_start, data_end).is_err() {
        return false;
    }
    let compiled = compiler.finish();

    // Inline fragments should have no substitution slots.
    if compiled.slots.is_empty() {
        // Add indent at the start of the fragment (first line)
        for _ in 0..indent_offset {
            buf.push(b' ');
        }
        for part in &compiled.parts {
            write_part_with_indent(buf, part, indent_offset);
        }
        return true;
    }

    // Has substitution slots — unexpected for inline fragments, bail.
    false
}

/// Handle the empty-optional indentation logic for raw rendering.
#[inline]
fn handle_raw_optional_empty(
    template: &CompiledXmlTemplate,
    buf: &mut Vec<u8>,
    slot: &SubSlot,
    slot_index: usize,
    indent: bool,
    indent_offset: usize,
) {
    if indent && !slot.in_attribute && buf.ends_with(b">") {
        if let Some(next_part) = template.parts.get(slot_index + 1) {
            if next_part.starts_with(b"</") && !next_part.starts_with(b"</Binary>") {
                buf.push(b'\n');
                let close_indent = indent_offset + slot.indent_level.saturating_sub(2);
                for _ in 0..close_indent {
                    buf.push(b' ');
                }
            }
        }
    }
}

/// Check if a raw value actually produces renderable content.
/// Used for attribute suppression: attributes with no content are omitted.
#[inline]
fn raw_value_has_content(raw: &[u8], value_type: u8) -> bool {
    match value_type {
        0x00 => false, // NullType — never has content
        0x01 => utf16le_content_length(raw) > 0, // StringType — check for NUL-only
        0x02 => raw.iter().any(|&b| b != 0), // AnsiString — check for NUL-only
        _ => !raw.is_empty(), // All other types: non-empty raw bytes = has content
    }
}

/// Split raw array bytes into individual item slices.
///
/// For StringArray (base 0x01): items are NUL-terminated UTF-16LE strings.
/// For fixed-size types: items are packed sequentially.
fn split_array_items<'r>(raw: &'r [u8], base_type: u8) -> Vec<&'r [u8]> {
    if base_type == 0x01 {
        // StringArray: split on UTF-16LE NUL terminators (0x0000)
        let mut items = Vec::new();
        let mut start = 0;
        let mut i = 0;
        while i + 1 < raw.len() {
            if raw[i] == 0 && raw[i + 1] == 0 {
                items.push(&raw[start..i]);
                start = i + 2;
                i = start;
            } else {
                i += 2;
            }
        }
        if start < raw.len() && raw[start..].iter().any(|&b| b != 0) {
            items.push(&raw[start..]);
        }
        items
    } else {
        let item_size = fixed_type_item_size(base_type);
        if item_size == 0 || raw.is_empty() {
            return Vec::new();
        }
        raw.chunks_exact(item_size).collect()
    }
}

/// Item size in bytes for fixed-size BinXml value types.
fn fixed_type_item_size(base_type: u8) -> usize {
    match base_type {
        0x03 | 0x04 => 1,                          // Int8, UInt8
        0x05 | 0x06 => 2,                          // Int16, UInt16
        0x07 | 0x08 | 0x0B | 0x0D | 0x14 => 4,    // Int32, UInt32, Real32, Bool, HexInt32
        0x09 | 0x0A | 0x0C | 0x11 | 0x15 => 8,    // Int64, UInt64, Real64, FileTime, HexInt64
        0x0F | 0x12 => 16,                         // Guid, SysTime
        _ => 0,
    }
}

/// Extract the element name from a raw opening tag like `  <Data Name="Foo">`.
/// Returns the name bytes between the first `<` and the first ` ` or `>`.
fn extract_element_name(raw_opening: &[u8]) -> &[u8] {
    let start = raw_opening.iter().position(|&b| b == b'<').map(|p| p + 1).unwrap_or(0);
    let end = raw_opening[start..]
        .iter()
        .position(|&b| b == b' ' || b == b'>')
        .map(|p| start + p)
        .unwrap_or(raw_opening.len());
    &raw_opening[start..end]
}

/// Format a single raw value into the buffer. Returns false on bail.
#[inline]
fn write_raw_value(
    buf: &mut Vec<u8>,
    raw: &[u8],
    value_type: u8,
    size: u16,
    in_attribute: bool,
    float_buf: &mut zmij::Buffer,
    fmt: &mut CompactFormatter,
) -> bool {
    match value_type {
        0x00 => {} // NullType — skip

        // StringType — UTF-16LE
        0x01 => {
            let content_len = utf16le_content_length(raw);
            if content_len > 0 {
                if utf16_simd::write_xml_utf16le(buf, &raw[..content_len], content_len / 2, in_attribute).is_err() {
                    return false;
                }
            }
        }

        // AnsiStringType — byte-by-byte with XML escaping, filtering NULs
        0x02 => {
            for &b in raw {
                if b == 0 {
                    continue; // Filter embedded NUL bytes
                }
                match b {
                    b'&' => buf.extend_from_slice(b"&amp;"),
                    b'<' => buf.extend_from_slice(b"&lt;"),
                    b'>' => buf.extend_from_slice(b"&gt;"),
                    b'"' if in_attribute => buf.extend_from_slice(b"&quot;"),
                    b'\'' if in_attribute => buf.extend_from_slice(b"&apos;"),
                    _ => buf.push(b),
                }
            }
        }

        // Int8
        0x03 => {
            if raw.len() < 1 { return false; }
            if fmt.write_i8(buf, raw[0] as i8).is_err() { return false; }
        }
        // UInt8
        0x04 => {
            if raw.len() < 1 { return false; }
            if fmt.write_u8(buf, raw[0]).is_err() { return false; }
        }
        // Int16
        0x05 => {
            if raw.len() < 2 { return false; }
            let v = i16::from_le_bytes([raw[0], raw[1]]);
            if fmt.write_i16(buf, v).is_err() { return false; }
        }
        // UInt16
        0x06 => {
            if raw.len() < 2 { return false; }
            let v = u16::from_le_bytes([raw[0], raw[1]]);
            if fmt.write_u16(buf, v).is_err() { return false; }
        }
        // Int32
        0x07 => {
            if raw.len() < 4 { return false; }
            let v = i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            if fmt.write_i32(buf, v).is_err() { return false; }
        }
        // UInt32
        0x08 => {
            if raw.len() < 4 { return false; }
            let v = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            if fmt.write_u32(buf, v).is_err() { return false; }
        }
        // Int64
        0x09 => {
            if raw.len() < 8 { return false; }
            let v = i64::from_le_bytes(raw[..8].try_into().unwrap());
            if fmt.write_i64(buf, v).is_err() { return false; }
        }
        // UInt64
        0x0A => {
            if raw.len() < 8 { return false; }
            let v = u64::from_le_bytes(raw[..8].try_into().unwrap());
            if fmt.write_u64(buf, v).is_err() { return false; }
        }
        // Real32
        0x0B => {
            if raw.len() < 4 { return false; }
            let v = f32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let s = float_buf.format(v);
            buf.extend_from_slice(s.as_bytes());
        }
        // Real64
        0x0C => {
            if raw.len() < 8 { return false; }
            let v = f64::from_le_bytes(raw[..8].try_into().unwrap());
            let s = float_buf.format(v);
            buf.extend_from_slice(s.as_bytes());
        }
        // BoolType
        0x0D => {
            if raw.len() < 4 { return false; }
            let v = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            buf.extend_from_slice(if v != 0 { b"true" } else { b"false" });
        }
        // BinaryType — hex upper
        0x0E => {
            write_hex_upper(buf, raw);
        }
        // GuidType
        0x0F => {
            if raw.len() < 16 { return false; }
            write_guid_raw(buf, raw);
        }
        // SizeTType — renders as hex based on size
        0x10 => {
            match size {
                4 => {
                    if raw.len() < 4 { return false; }
                    let v = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
                    write_hex_prefixed_u32(buf, v);
                }
                8 => {
                    if raw.len() < 8 { return false; }
                    let v = u64::from_le_bytes(raw[..8].try_into().unwrap());
                    write_hex_prefixed_u64(buf, v);
                }
                _ => return false,
            }
        }
        // FileTimeType
        0x11 => {
            if raw.len() < 8 { return false; }
            let ft = u64::from_le_bytes(raw[..8].try_into().unwrap());
            write_filetime_raw(buf, ft);
        }
        // SysTimeType
        0x12 => {
            if raw.len() < 16 { return false; }
            write_systime_raw(buf, raw);
        }
        // SidType
        0x13 => {
            write_sid_raw(buf, raw);
        }
        // HexInt32Type
        0x14 => {
            if raw.len() < 4 { return false; }
            let v = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            write_hex_prefixed_u32(buf, v);
        }
        // HexInt64Type
        0x15 => {
            if raw.len() < 8 { return false; }
            let v = u64::from_le_bytes(raw[..8].try_into().unwrap());
            write_hex_prefixed_u64(buf, v);
        }

        // Anything else (EvtHandle 0x20, BinXml 0x21, EvtXml 0x23, arrays 0x80+)
        // should have been caught before this function is called.
        _ => return false,
    }
    true
}

/// Find the content length of a UTF-16LE byte slice, stopping at the first NUL u16.
/// This matches `utf16_by_char_count`'s NUL-trimming behavior.
#[inline]
fn utf16le_content_length(raw: &[u8]) -> usize {
    for (idx, chunk) in raw.chunks_exact(2).enumerate() {
        if chunk[0] == 0 && chunk[1] == 0 {
            return idx * 2;
        }
    }
    // No NUL found; use all bytes (truncated to even length)
    raw.len() & !1
}

/// Write bytes as uppercase hex (e.g. "0A1B2C").
#[inline]
fn write_hex_upper(buf: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    buf.reserve(bytes.len() * 2);
    for &b in bytes {
        buf.push(HEX[(b >> 4) as usize]);
        buf.push(HEX[(b & 0x0F) as usize]);
    }
}

/// Write a GUID from 16 raw bytes in standard format: `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`.
#[inline]
fn write_guid_raw(buf: &mut Vec<u8>, raw: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    #[inline]
    fn hex2(buf: &mut Vec<u8>, b: u8) {
        buf.push(HEX[(b >> 4) as usize]);
        buf.push(HEX[(b & 0x0F) as usize]);
    }

    // Data1: u32 LE → 8 hex chars (big-endian display)
    let d1 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    hex2(buf, (d1 >> 24) as u8);
    hex2(buf, (d1 >> 16) as u8);
    hex2(buf, (d1 >> 8) as u8);
    hex2(buf, d1 as u8);

    buf.push(b'-');

    // Data2: u16 LE → 4 hex chars
    let d2 = u16::from_le_bytes([raw[4], raw[5]]);
    hex2(buf, (d2 >> 8) as u8);
    hex2(buf, d2 as u8);

    buf.push(b'-');

    // Data3: u16 LE → 4 hex chars
    let d3 = u16::from_le_bytes([raw[6], raw[7]]);
    hex2(buf, (d3 >> 8) as u8);
    hex2(buf, d3 as u8);

    buf.push(b'-');

    // Data4 bytes 0-1 → 4 hex chars
    hex2(buf, raw[8]);
    hex2(buf, raw[9]);

    buf.push(b'-');

    // Data4 bytes 2-7 → 12 hex chars
    hex2(buf, raw[10]);
    hex2(buf, raw[11]);
    hex2(buf, raw[12]);
    hex2(buf, raw[13]);
    hex2(buf, raw[14]);
    hex2(buf, raw[15]);
}

/// Write a FILETIME (u64, 100ns ticks since 1601-01-01) as `yyyy-MM-ddTHH:mm:ss.ffffffZ`.
fn write_filetime_raw(buf: &mut Vec<u8>, ft: u64) {
    const WINDOWS_TO_UNIX_SECS: i64 = 11_644_473_600;
    const TICKS_PER_SEC: u64 = 10_000_000;

    let total_secs = (ft / TICKS_PER_SEC) as i64;
    let unix_secs = total_secs - WINDOWS_TO_UNIX_SECS;
    let micros = ((ft % TICKS_PER_SEC) / 10) as u32;

    let unix_days = unix_secs.div_euclid(86400);
    let day_secs = unix_secs.rem_euclid(86400) as u32;

    let (year, month, day) = civil_from_days(unix_days);
    let hour = day_secs / 3600;
    let minute = (day_secs % 3600) / 60;
    let second = day_secs % 60;

    write_datetime_components(buf, year, month, day, hour, minute, second, micros);
}

/// Write a SYSTEMTIME (16 raw bytes: 8 × u16 LE) as `yyyy-MM-ddTHH:mm:ss.ffffffZ`.
fn write_systime_raw(buf: &mut Vec<u8>, raw: &[u8]) {
    let year = u16::from_le_bytes([raw[0], raw[1]]);
    let month = u16::from_le_bytes([raw[2], raw[3]]);
    // raw[4..6] = day_of_week (ignored)
    let day = u16::from_le_bytes([raw[6], raw[7]]);
    let hour = u16::from_le_bytes([raw[8], raw[9]]);
    let minute = u16::from_le_bytes([raw[10], raw[11]]);
    let second = u16::from_le_bytes([raw[12], raw[13]]);
    let millis = u16::from_le_bytes([raw[14], raw[15]]);

    // All zeros → convention: 1601-01-01T00:00:00.000000Z
    if year == 0 && month == 0 && day == 0 && hour == 0 && minute == 0 && second == 0 && millis == 0 {
        write_filetime_raw(buf, 0);
        return;
    }

    let micros = u32::from(millis) * 1000;
    write_datetime_components(
        buf,
        i32::from(year),
        u32::from(month),
        u32::from(day),
        u32::from(hour),
        u32::from(minute),
        u32::from(second),
        micros,
    );
}

/// Write `yyyy-MM-ddTHH:mm:ss.ffffffZ` from components.
#[inline]
fn write_datetime_components(
    buf: &mut Vec<u8>,
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    micros: u32,
) {
    buf.reserve(27); // "yyyy-MM-ddTHH:mm:ss.ffffffZ"

    // Year (4 digits)
    let y = year as u32;
    buf.push(b'0' + ((y / 1000) % 10) as u8);
    buf.push(b'0' + ((y / 100) % 10) as u8);
    buf.push(b'0' + ((y / 10) % 10) as u8);
    buf.push(b'0' + (y % 10) as u8);
    buf.push(b'-');

    // Month (2 digits)
    buf.push(b'0' + ((month / 10) % 10) as u8);
    buf.push(b'0' + (month % 10) as u8);
    buf.push(b'-');

    // Day (2 digits)
    buf.push(b'0' + ((day / 10) % 10) as u8);
    buf.push(b'0' + (day % 10) as u8);
    buf.push(b'T');

    // Hour (2 digits)
    buf.push(b'0' + ((hour / 10) % 10) as u8);
    buf.push(b'0' + (hour % 10) as u8);
    buf.push(b':');

    // Minute (2 digits)
    buf.push(b'0' + ((minute / 10) % 10) as u8);
    buf.push(b'0' + (minute % 10) as u8);
    buf.push(b':');

    // Second (2 digits)
    buf.push(b'0' + ((second / 10) % 10) as u8);
    buf.push(b'0' + (second % 10) as u8);
    buf.push(b'.');

    // Microseconds (6 digits)
    buf.push(b'0' + ((micros / 100000) % 10) as u8);
    buf.push(b'0' + ((micros / 10000) % 10) as u8);
    buf.push(b'0' + ((micros / 1000) % 10) as u8);
    buf.push(b'0' + ((micros / 100) % 10) as u8);
    buf.push(b'0' + ((micros / 10) % 10) as u8);
    buf.push(b'0' + (micros % 10) as u8);
    buf.push(b'Z');
}

/// Convert Unix days (days since 1970-01-01) to (year, month, day).
///
/// Uses the algorithm by Howard Hinnant:
/// <https://howardhinnant.github.io/date_algorithms.html>
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719468; // shift epoch from 1970-01-01 to 0000-03-01
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

/// Write a SID directly from raw bytes as `S-{rev}-{auth}-{sub1}-{sub2}-...`.
fn write_sid_raw(buf: &mut Vec<u8>, raw: &[u8]) {
    if raw.len() < 8 {
        buf.extend_from_slice(b"S-?");
        return;
    }

    let revision = raw[0];
    let sub_count = raw[1] as usize;

    // IdentifierAuthority: 48-bit big-endian integer
    let mut authority: u64 = 0;
    for &b in &raw[2..8] {
        authority = (authority << 8) | u64::from(b);
    }

    buf.extend_from_slice(b"S-");
    write_u64_decimal(buf, u64::from(revision));
    buf.push(b'-');
    write_u64_decimal(buf, authority);

    let mut off = 8usize;
    for _ in 0..sub_count {
        if off + 4 > raw.len() {
            break;
        }
        let sub = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
        buf.push(b'-');
        write_u64_decimal(buf, u64::from(sub));
        off += 4;
    }
}

/// Write `0x` followed by minimal lowercase hex digits for a u32.
#[inline]
fn write_hex_prefixed_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(b"0x");
    write_hex_lower_u64(buf, u64::from(value));
}

/// Write `0x` followed by minimal lowercase hex digits for a u64.
#[inline]
fn write_hex_prefixed_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(b"0x");
    write_hex_lower_u64(buf, value);
}

/// Write minimal lowercase hex digits for a u64 (no prefix).
fn write_hex_lower_u64(buf: &mut Vec<u8>, mut value: u64) {
    if value == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 16];
    let mut len = 0usize;
    while value != 0 {
        let nib = (value & 0x0F) as u8;
        tmp[len] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
        len += 1;
        value >>= 4;
    }
    // Reverse
    for i in (0..len).rev() {
        buf.push(tmp[i]);
    }
}

/// Write a u64 as decimal digits.
fn write_u64_decimal(buf: &mut Vec<u8>, value: u64) {
    if value == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    let mut n = value;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
    }
    for i in (0..len).rev() {
        buf.push(tmp[i]);
    }
}
