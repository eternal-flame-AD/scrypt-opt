use core::ops::{Deref, DerefMut};

use generic_array::{ArrayLength, typenum::NonZero};

use crate::{Block, BlockU8};

#[repr(align(64))]
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
/// Align to 64 bytes
pub struct Align64<T>(pub T);

impl<R: ArrayLength + NonZero> Align64<Block<R>> {
    /// Transmute the block buffer to a u8 array
    pub const fn transmute_as_u8(&self) -> &Align64<BlockU8<R>> {
        unsafe { generic_array::const_transmute(&self.0) }
    }

    /// Transmute the block buffer to a mutable u8 array
    pub const fn transmute_as_u8_mut(&mut self) -> &mut Align64<BlockU8<R>> {
        unsafe { generic_array::const_transmute(&mut self.0) }
    }
}

impl<T> AsRef<T> for Align64<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> AsRef<Align64<T>> for Align64<T> {
    fn as_ref(&self) -> &Align64<T> {
        self
    }
}

impl<T> AsMut<Align64<T>> for Align64<T> {
    fn as_mut(&mut self) -> &mut Align64<T> {
        self
    }
}

impl<T> AsMut<T> for Align64<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> Deref for Align64<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Align64<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A box for a hugepage-backed buffer
#[cfg(feature = "huge-page")]
pub struct HugeSlice<T> {
    ptr: *mut T,
    len: usize,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    capacity: usize,
}

#[cfg(feature = "huge-page")]
unsafe impl<T> Send for HugeSlice<T> where T: Send {}

#[cfg(feature = "huge-page")]
unsafe impl<T> Sync for HugeSlice<T> where T: Sync {}

#[cfg(feature = "huge-page")]
impl<T> core::convert::AsMut<T> for HugeSlice<T> {
    fn as_mut(&mut self) -> &mut T {
        unsafe { &mut *self.ptr }
    }
}

#[cfg(feature = "huge-page")]
impl<T> HugeSlice<T> {
    /// Create a new hugepage-backed buffer
    #[cfg(target_os = "windows")]
    pub fn new(len: usize) -> Result<Self, std::io::Error> {
        use windows_sys::Win32::{
            Security::TOKEN_ADJUST_PRIVILEGES,
            System::{
                Memory::{
                    GetLargePageMinimum, MEM_COMMIT, MEM_LARGE_PAGES, MEM_RESERVE, PAGE_READWRITE,
                    VirtualAlloc,
                },
                Threading::{GetCurrentProcess, OpenProcessToken},
            },
        };
        unsafe {
            use windows_sys::Win32::Security::{
                AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueA,
                SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES,
            };

            let min_alloc_size = core::mem::size_of::<T>() * len;
            if min_alloc_size == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Allocation size must be non-zero",
                ));
            }

            let large_page_minimum = GetLargePageMinimum();
            if large_page_minimum == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Large page not supported by the system",
                ));
            }

            if large_page_minimum < core::mem::align_of::<T>() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "Large page minimum ({}) is less than the alignment of the type {} ({})",
                        large_page_minimum,
                        core::any::type_name::<T>(),
                        core::mem::align_of::<T>()
                    ),
                ));
            }

            let mut token_handle = Default::default();
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES,
                &mut token_handle,
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }

            let mut privs = [TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: Default::default(),
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            }];

            if LookupPrivilegeValueA(
                core::ptr::null_mut(),
                c"SeLockMemoryPrivilege".as_ptr().cast(),
                &mut privs[0].Privileges[0].Luid,
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }

            if AdjustTokenPrivileges(
                token_handle,
                0,
                privs.as_ptr(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            ) == 0
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to adjust token privileges",
                ));
            }

            let ptr = VirtualAlloc(
                core::ptr::null_mut(),
                min_alloc_size.next_multiple_of(large_page_minimum),
                MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES,
                PAGE_READWRITE,
            );

            if ptr == core::ptr::null_mut() {
                return Err(std::io::Error::last_os_error());
            }

            Ok(Self {
                ptr: ptr.cast::<T>(),
                len,
            })
        }
    }

    /// Create a new hugepage-backed buffer
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub fn new(len: usize) -> Result<Self, std::io::Error> {
        unsafe {
            let pagesz = libc::sysconf(libc::_SC_PAGESIZE);
            if pagesz == -1 {
                return Err(std::io::Error::last_os_error());
            }

            let page_size = pagesz as usize;
            if core::mem::align_of::<T>() > page_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "Alignment of the type is greater than the page size: {} requires {} alignment, page size is {}",
                        core::any::type_name::<T>(),
                        core::mem::align_of::<T>(),
                        page_size
                    ),
                ));
            }

            let alloc_min_len = core::mem::size_of::<T>() * len;

            if alloc_min_len == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Allocation length must be non-zero",
                ));
            }

            for (try_page_size, try_flags) in [
                #[cfg(target_os = "linux")]
                ((1 << 30), libc::MAP_HUGE_1GB),
                #[cfg(target_os = "linux")]
                ((256 << 20), libc::MAP_HUGE_256MB),
                #[cfg(target_os = "linux")]
                ((32 << 20), libc::MAP_HUGE_32MB),
                #[cfg(target_os = "linux")]
                ((16 << 20), libc::MAP_HUGE_16MB),
                #[cfg(target_os = "linux")]
                ((8 << 20), libc::MAP_HUGE_8MB),
                ((page_size), 0),
            ]
            .into_iter()
            .filter(|(try_page_size, _flags)| *try_page_size >= page_size)
            // don't grossly over size by capping page size at 2x amount of memory needed
            .filter(|(try_page_size, flags)| *flags == 0 || alloc_min_len * 2 > *try_page_size)
            {
                let try_size = alloc_min_len.next_multiple_of(try_page_size);
                let ptr = libc::mmap64(
                    core::ptr::null_mut(),
                    try_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE
                        | libc::MAP_ANONYMOUS
                        | libc::MAP_HUGETLB
                        | libc::MAP_POPULATE
                        | try_flags,
                    -1,
                    0,
                );
                if ptr != libc::MAP_FAILED {
                    return Ok(HugeSlice {
                        ptr: ptr.cast::<T>(),
                        len,
                        capacity: try_size,
                    });
                }
            }
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(all(
        not(target_os = "windows"),
        not(target_os = "android"),
        not(target_os = "linux")
    ))]
    pub fn new(len: usize) -> Result<Self, std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Huge page not supported on this platform",
        ))
    }
}

#[cfg(feature = "huge-page")]
impl<T> HugeSlice<core::mem::MaybeUninit<T>> {
    /// Assume the buffer is initialized
    pub unsafe fn assume_init(self) -> HugeSlice<T> {
        HugeSlice {
            ptr: self.ptr.cast::<T>(),
            len: self.len,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            capacity: self.capacity,
        }
    }
}

#[cfg(feature = "huge-page")]
impl<T> core::convert::AsRef<[T]> for HugeSlice<T> {
    fn as_ref(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

#[cfg(feature = "huge-page")]
impl<T> core::convert::AsMut<[T]> for HugeSlice<T> {
    fn as_mut(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

#[cfg(feature = "huge-page")]
impl<T> core::ops::Deref for HugeSlice<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

#[cfg(feature = "huge-page")]
impl<T> core::ops::DerefMut for HugeSlice<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

#[cfg(feature = "huge-page")]
impl<T> Drop for HugeSlice<T> {
    #[cfg(target_os = "windows")]
    fn drop(&mut self) {
        use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree};
        unsafe {
            debug_assert!(
                VirtualFree(self.ptr as *mut _, 0, MEM_RELEASE) != 0,
                "Failed to free huge page"
            );
        }
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.capacity);
        }
    }

    #[cfg(all(
        not(target_os = "windows"),
        not(target_os = "android"),
        not(target_os = "linux")
    ))]
    fn drop(&mut self) {
        // Do nothing
    }
}

#[cfg(feature = "alloc")]
/// A box for a buffer that can be backed by a huge page or a normal box
pub enum MaybeHugeSlice<T> {
    #[cfg(feature = "huge-page")]
    /// A huge page-backed buffer
    Huge(HugeSlice<T>),
    /// A normal buffer backed by heap
    Normal(alloc::boxed::Box<[T]>),
}

impl<T> core::ops::Deref for MaybeHugeSlice<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T> core::ops::DerefMut for MaybeHugeSlice<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<T> AsRef<[T]> for MaybeHugeSlice<T> {
    fn as_ref(&self) -> &[T] {
        match self {
            #[cfg(feature = "huge-page")]
            MaybeHugeSlice::Huge(b) => b.as_ref(),
            MaybeHugeSlice::Normal(b) => b,
        }
    }
}

impl<T> core::convert::AsMut<[T]> for MaybeHugeSlice<T> {
    fn as_mut(&mut self) -> &mut [T] {
        match self {
            #[cfg(feature = "huge-page")]
            MaybeHugeSlice::Huge(b) => b.as_mut(),
            MaybeHugeSlice::Normal(b) => b.as_mut(),
        }
    }
}

impl<T> MaybeHugeSlice<T> {
    /// Check if the buffer is backed by a huge page
    pub fn is_huge_page(&self) -> bool {
        match self {
            #[cfg(feature = "huge-page")]
            MaybeHugeSlice::Huge(_) => true,
            MaybeHugeSlice::Normal(_) => false,
        }
    }

    /// Create a new huge page-backed buffer
    #[cfg(feature = "huge-page")]
    pub fn new_huge_slice_zeroed(len: usize) -> Result<Self, std::io::Error> {
        let b: HugeSlice<core::mem::MaybeUninit<T>> = HugeSlice::new(len)?;
        unsafe {
            core::slice::from_raw_parts_mut(b.ptr.cast::<u8>(), len * core::mem::size_of::<T>())
                .fill(0);
            Ok(MaybeHugeSlice::Huge(b.assume_init()))
        }
    }

    /// Create a new normal buffer
    #[cfg(feature = "alloc")]
    pub fn new_slice_zeroed(len: usize) -> Self {
        let mut b = alloc::vec::Vec::<T>::with_capacity(len);
        unsafe {
            b.set_len(len);
            MaybeHugeSlice::Normal(b.into())
        }
    }

    /// Create a new buffer
    #[cfg(feature = "alloc")]
    pub fn new_maybe(len: usize) -> Self {
        #[cfg(feature = "huge-page")]
        {
            match Self::new_huge_slice_zeroed(len) {
                Ok(huge) => huge,
                Err(_) => Self::new_slice_zeroed(len),
            }
        }

        #[cfg(not(feature = "huge-page"))]
        Self::new_slice_zeroed(len)
    }

    /// Create a new buffer
    #[cfg(feature = "std")]
    pub fn new(len: usize) -> (Self, Option<std::io::Error>) {
        #[cfg(feature = "huge-page")]
        {
            match Self::new_huge_slice_zeroed(len) {
                Ok(huge) => (huge, None),
                Err(e) => (Self::new_slice_zeroed(len), Some(e.into())),
            }
        }

        #[cfg(not(feature = "huge-page"))]
        (Self::new_slice_zeroed(len), None)
    }
}
