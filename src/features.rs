use core::sync::atomic::{AtomicU8, Ordering};

/// A feature that can be checked at runtime.
pub trait Feature {
    /// The name of the feature.
    fn name(&self) -> &'static str;

    /// Whether the feature is required for the crate to work.
    fn required(&self) -> bool;

    /// The length of the vector in bytes.
    fn vector_length(&self) -> usize;

    /// Checks if the feature is supported at runtime.
    fn check_volatile(&self) -> bool;

    /// Checks if the feature is supported.
    fn check(&self) -> bool {
        if self.required() {
            return true;
        }

        static RESULT: AtomicU8 = AtomicU8::new(0);

        let mut result = RESULT.load(Ordering::Relaxed);
        if result == 0 {
            let detected = self.check_volatile();
            result = if detected { 1 } else { !0 };
            RESULT.fetch_max(result, Ordering::Relaxed);
        }
        result == 1
    }
}

/// Iterates over all features.
#[cfg_attr(not(target_arch = "x86_64"), expect(unused))]
pub fn iterate<F: FnMut(&dyn Feature)>(mut f: F) {
    #[cfg(target_arch = "x86_64")]
    {
        f(&Avx2);
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Default)]
/// AVX2 feature.
pub struct Avx2;

#[cfg(target_arch = "x86_64")]
impl Feature for Avx2 {
    fn name(&self) -> &'static str {
        "avx2"
    }

    fn required(&self) -> bool {
        cfg!(target_feature = "avx2")
    }

    fn vector_length(&self) -> usize {
        32
    }

    fn check_volatile(&self) -> bool {
        #[cfg(not(feature = "std"))]
        unsafe {
            core::arch::x86_64::__cpuid(7).ebx & (1 << 5) != 0
        }
        #[cfg(feature = "std")]
        std::arch::is_x86_feature_detected!("avx2")
    }
}

#[cfg(test)]
mod tests {
    #[cfg_attr(not(target_arch = "x86_64"), expect(unused_imports))]
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_avx2() {
        if !cfg!(target_feature = "avx2") {
            assert_eq!(Avx2.check(), std::arch::is_x86_feature_detected!("avx2"));
        } else {
            assert!(Avx2.check());
            assert_eq!(
                Avx2.check_volatile(),
                std::arch::is_x86_feature_detected!("avx2")
            );
        }
    }
}
