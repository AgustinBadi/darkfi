window.SIDEBAR_ITEMS = {"enum":[["CustomPlace","Possible locations to place a custom section within a module."],["CustomPlaceAnchor","Known sections that custom sections can be placed relative to."],["DataKind","Different kinds of data segments, either passive or active."],["DataVal","Differnet ways the value of a data segment can be defined."],["ElemKind","Different ways to define an element segment in an mdoule."],["ElemPayload","Different ways to define the element segment payload in a module."],["ExportKind","Different kinds of elements that can be exported from a WebAssembly module, contained in an [`Export`]."],["FuncKind","Possible ways to define a function in the text format."],["GlobalKind","Different kinds of globals that can be defined in a module."],["HeapType","A heap type for a reference type"],["Instruction","A listing of all WebAssembly instructions that can be in a module that this crate currently parses."],["ItemKind",""],["MemoryKind","Different syntactical ways a memory can be defined in a module."],["MemoryType","Configuration for a memory of a wasm module"],["ModuleField","A listing of all possible fields that can make up a WebAssembly module."],["ModuleKind","The different kinds of ways to define a module."],["NanPattern","Either a NaN pattern (`nan:canonical`, `nan:arithmetic`) or a value of type `T`."],["StorageType","The types of values that may be used in a struct or array."],["TableKind","Different ways to textually define a table."],["TagKind","Different kinds of tags that can be defined in a module."],["TagType","Listing of various types of tags that can be defined in a wasm module."],["TypeDef","A definition of a type."],["V128Const","Different ways to specify a `v128.const` instruction"],["V128Pattern","A version of `V128Const` that allows `NanPattern`s."],["ValType","The value types for a wasm module."],["WastArgCore","Expression that can be used inside of `invoke` expressions for core wasm functions."],["WastRetCore","Expressions that can be used inside of `assert_return` to validate the return value of a core wasm function."]],"struct":[["ArrayCopy","Extra data associated with the `array.copy` instruction"],["ArrayFill","Extra data associated with the `array.fill` instruction"],["ArrayInit","Extra data associated with the `array.init_[data/elem]` instruction"],["ArrayNewData","Extra data associated with the `array.new_data` instruction"],["ArrayNewElem","Extra data associated with the `array.new_elem` instruction"],["ArrayNewFixed","Extra data associated with the `array.new_fixed` instruction"],["ArrayType","An array type with fields."],["BlockType","Extra information associated with block-related instructions."],["BrOnCast","Extra data associated with the `br_on_cast` instruction"],["BrOnCastFail","Extra data associated with the `br_on_cast_fail` instruction"],["BrTableIndices","Extra information associated with the `br_table` instruction."],["CallIndirect","Extra data associated with the `call_indirect` instruction."],["Custom","A wasm custom section within a module."],["Data","A `data` directive in a WebAssembly module."],["Elem","An `elem` segment in a WebAssembly module."],["Export","A entry in a WebAssembly module’s export section."],["ExportType","The type of an exported item from a module or instance."],["Expression","An expression, or a list of instructions, in the WebAssembly text format."],["Func","A WebAssembly function to be inserted into a module."],["FuncBindType","Extra information associated with the func.bind instruction."],["FunctionType","A function type with parameters and results."],["FunctionTypeNoNames","A function type with parameters and results."],["Global","A WebAssembly global in a module"],["GlobalType","Type for a `global` in a wasm module"],["I8x16Shuffle","Lanes being shuffled in the `i8x16.shuffle` instruction"],["Import","An `import` statement and entry in a WebAssembly module."],["InlineExport","A listing of inline `(export \"foo\")` statements on a WebAssembly item in its textual format."],["InlineImport","A listing of a inline `(import \"foo\")` statement."],["ItemSig",""],["LaneArg","Payload for lane-related instructions. Unsigned with no + prefix."],["LetType","Extra information associated with the let instruction."],["Limits","Min/max limits used for tables/memories."],["Limits64","Min/max limits used for 64-bit memories"],["LoadOrStoreLane","Extra data associated with the `loadN_lane` and `storeN_lane` instructions."],["Local","A local for a `func` or `let` instruction."],["MemArg","Payload for memory-related instructions indicating offset/alignment of memory accesses."],["Memory","A defined WebAssembly memory instance inside of a module."],["MemoryArg","Extra data associated with unary memory instructions."],["MemoryCopy","Extra data associated with the `memory.copy` instruction"],["MemoryInit","Extra data associated with the `memory.init` instruction"],["Module","A parsed WebAssembly core module."],["Names","Representation of the results of name resolution for a module."],["Rec","A recursion group declaration in a module"],["RefCast","Extra data associated with the `ref.cast` instruction"],["RefTest","Extra data associated with the `ref.test` instruction"],["RefType","A reference type in a wasm module."],["SelectTypes","Payload of the `select` instructions"],["StructAccess","Extra data associated with the `struct.get/set` instructions"],["StructField","A field of a struct type."],["StructType","A struct type with fields."],["Table","A WebAssembly `table` directive in a module."],["TableArg","Extra data associated with unary table instructions."],["TableCopy","Extra data associated with the `table.copy` instruction."],["TableInit","Extra data associated with the `table.init` instruction"],["TableType","Configuration for a table of a wasm mdoule"],["Tag","A WebAssembly tag directive, part of the exception handling proposal."],["Type","A type declaration in a module"],["TypeUse","A reference to a type defined in this module."]]};