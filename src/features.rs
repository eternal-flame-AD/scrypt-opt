/// A feature that can be checked at runtime.
pub trait Feature {
    /// The name of the feature.
    fn name(&self) -> &'static str;

    /// Whether the feature is required for the crate to work.
    fn required(&self) -> bool;

    /// The length of the vector in bytes.
    fn vector_length(&self) -> usize;

    /// Checks if the feature is supported.
    fn check(&self) -> bool {
        if self.required() {
            return true;
        }

        self.check_volatile()
    }

    /// Checks if the feature is supported at runtime.
    fn check_volatile(&self) -> bool;
}

/// Iterates over all features.
#[cfg_attr(not(target_arch = "x86_64"), expect(unused))]
pub fn iterate<F: FnMut(&dyn Feature)>(mut f: F) {
    #[cfg(target_arch = "x86_64")]
    {
        f(&Avx2);
        f(&Avx512F);
        f(&Avx512VL);
    }
}

macro_rules! define_x86_feature {
    ($name:ident, $cpuid_name:ident, $feature:tt) => {
        #[cfg(target_arch = "x86_64")]
        cpufeatures::new!($cpuid_name, $feature);

        #[cfg(target_arch = "x86_64")]
        #[derive(Default)]
        #[doc = concat!("X86 ", stringify!($feature), " feature.")]
        pub struct $name;

        #[cfg(target_arch = "x86_64")]
        impl Feature for $name {
            fn name(&self) -> &'static str {
                stringify!($feature)
            }

            fn required(&self) -> bool {
                cfg!(target_feature = $feature)
            }

            fn vector_length(&self) -> usize {
                32
            }

            fn check_volatile(&self) -> bool {
                $cpuid_name::get()
            }
        }
    };
}

define_x86_feature!(Avx2, cpuid_avx2, "avx2");
define_x86_feature!(Avx512F, cpuid_avx512f, "avx512f");
define_x86_feature!(Avx512VL, cpuid_avx512vl, "avx512vl");

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
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_avx512f() {
        if !cfg!(target_feature = "avx512f") {
            assert_eq!(
                Avx512F.check(),
                std::arch::is_x86_feature_detected!("avx512f")
            );
        } else {
            assert!(Avx512F.check());
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_avx512vl() {
        if !cfg!(target_feature = "avx512vl") {
            assert_eq!(
                Avx512VL.check(),
                std::arch::is_x86_feature_detected!("avx512vl")
            );
        } else {
            assert!(Avx512VL.check());
        }
    }
}
