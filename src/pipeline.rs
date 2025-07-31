use crate::{
    Align64,
    fixed_r::{Block, BufferSet},
};
use generic_array::{ArrayLength, typenum::NonZero};

/// A context for a pipeline computation.
///
/// It is already implemented for `(&'a Align64<Block<R>>, &'b mut BlockU8<R>)` and `(&'a Align64<Block<R>>, &'b mut Align64<BlockU8<R>>)`
pub trait PipelineContext<
    S,
    Q: AsRef<[Align64<Block<R>>]> + AsMut<[Align64<Block<R>>]>,
    R: ArrayLength + NonZero,
    K,
>
{
    /// Called to initialize each computation.
    fn begin(&mut self, state: &mut S, buffer_set: &mut BufferSet<Q, R>);

    /// Called to process the result of each computation.
    ///
    /// Returns `Some(K)` if the computation should be terminated.
    fn drain(self, state: &mut S, buffer_set: &mut BufferSet<Q, R>) -> Option<K>;
}

impl<
    'a,
    'b,
    S,
    Q: AsRef<[Align64<Block<R>>]> + AsMut<[Align64<Block<R>>]>,
    R: ArrayLength + NonZero,
> PipelineContext<S, Q, R, ()> for (&'a Align64<Block<R>>, &'b mut Align64<Block<R>>)
{
    #[inline(always)]
    fn begin(&mut self, _state: &mut S, buffer_set: &mut BufferSet<Q, R>) {
        buffer_set.input_buffer_mut().copy_from_slice(self.0);
    }

    #[inline(always)]
    fn drain(self, _state: &mut S, buffer_set: &mut BufferSet<Q, R>) -> Option<()> {
        self.1.copy_from_slice(buffer_set.raw_salt_output());
        None
    }
}
