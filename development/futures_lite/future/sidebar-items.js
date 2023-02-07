window.SIDEBAR_ITEMS = {"fn":[["block_on","Blocks the current thread on a future."],["or","Returns the result of the future that completes first, preferring `future1` if both are ready."],["pending","Creates a future that is always pending."],["poll_fn","Creates a future from a function returning [`Poll`]."],["poll_once","Polls a future just once and returns an [`Option`] with the result."],["race","Returns the result of the future that completes first, with no preference if both are ready."],["ready","Creates a future that resolves to the provided value."],["try_zip","Joins two fallible futures, waiting for both to complete or one of them to error."],["yield_now","Wakes the current task and returns [`Poll::Pending`] once."],["zip","Joins two futures, waiting for both to complete."]],"struct":[["CatchUnwind","Future for the [`FutureExt::catch_unwind()`] method."],["Or","Future for the [`or()`] function and the [`FutureExt::or()`] method."],["Pending","Future for the [`pending()`] function."],["PollFn","Future for the [`poll_fn()`] function."],["PollOnce","Future for the [`poll_once()`] function."],["Race","Future for the [`race()`] function and the [`FutureExt::race()`] method."],["Ready","Future for the [`ready()`] function."],["TryZip","Future for the [`try_zip()`] function."],["YieldNow","Future for the [`yield_now()`] function."],["Zip","Future for the [`zip()`] function."]],"trait":[["FutureExt","Extension trait for [`Future`]."]],"type":[["Boxed","Type alias for `Pin<Box<dyn Future<Output = T> + Send + 'static>>`."],["BoxedLocal","Type alias for `Pin<Box<dyn Future<Output = T> + 'static>>`."]]};