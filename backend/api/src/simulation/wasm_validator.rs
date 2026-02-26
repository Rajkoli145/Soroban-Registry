use serde::{Deserialize, Serialize};
use wasmparser::Parser;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub function_count: u32,
    pub table_count: u32,
    pub data_section_size: u32,
    pub memory_pages: u64,
    pub export_functions: Vec<String>,
    pub import_functions: Vec<String>,
}

pub fn validate_wasm(wasm_bytes: &[u8]) -> WasmValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut function_count = 0u32;
    let mut table_count = 0u32;
    let mut data_section_size = 0u32;
    let mut memory_pages = 0u64;
    let mut export_functions = Vec::new();
    let mut import_functions = Vec::new();

    let parser = Parser::new(0);

    for payload in parser.parse_all(wasm_bytes) {
        match payload {
            Ok(wasmparser::Payload::Version { num, .. }) => {
                if num != 1 {
                    warnings.push(format!("Unusual WASM version: {}", num));
                }
            }
            Ok(wasmparser::Payload::FunctionSection(f)) => {
                function_count = f.count();
            }
            Ok(wasmparser::Payload::TableSection(t)) => {
                table_count = t.count();
            }
            Ok(wasmparser::Payload::MemorySection(m)) => {
                for memory in m {
                    if let Ok(mem) = memory {
                        memory_pages = mem.initial;
                    }
                }
            }
            Ok(wasmparser::Payload::DataSection(d)) => {
                data_section_size = d.count();
            }
            Ok(wasmparser::Payload::ExportSection(e)) => {
                for export in e {
                    if let Ok(exp) = export {
                        export_functions.push(exp.name.to_string());
                    }
                }
            }
            Ok(wasmparser::Payload::ImportSection(i)) => {
                for import in i {
                    if let Ok(imp) = import {
                        let name = format!("{}::{}", imp.module, imp.name);
                        import_functions.push(name);
                    }
                }
            }
            Ok(wasmparser::Payload::CodeSectionStart { count, .. }) => {
                if count == 0 {
                    warnings.push("No code section found - contract may be empty".to_string());
                }
            }
            Err(e) => {
                errors.push(format!("WASM parsing error: {}", e));
            }
            _ => {}
        }
    }

    let valid = errors.is_empty();

    if function_count == 0 {
        errors.push("No functions found in WASM binary".to_string());
    }

    if export_functions.is_empty() {
        warnings.push("No exported functions found".to_string());
    }

    WasmValidationResult {
        valid,
        errors,
        warnings,
        function_count,
        table_count,
        data_section_size,
        memory_pages,
        export_functions,
        import_functions,
    }
}
