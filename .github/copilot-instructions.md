When performing a code review, please evaluate whether your identified errors would have caused the unit tests to fail.
If so, the code is likely correct as they are checked by the unit tests.

With that being said, please still flag highly confusing/unclear/unreadable code (variable names does not make sense, etc.)

salsa20::BlockScalar is a reference implementation that is mainly used as source of truth for testing and as a final fallback to ensure successful compilation under all circumstances.
Ignore performance nitpicks on salsa20::BlockScalar, the whole code base is designed around the assumption that at least 256-bit SIMD is available (and you will compile with appropriate features enabled).