window.SIDEBAR_ITEMS = {"enum":[["CloseStatus","Conveys additional information regarding the status of a channel following a `close` operation."],["TryReceiveError","The error which is returned when trying to receive from a channel without waiting fails."],["TrySendError","The error which is returned when trying to send on a channel without waiting fails."]],"mod":[["shared","Channel implementations where Sender and Receiver sides are cloneable and owned. The Futures produced by channels in this module don’t require a lifetime parameter."]],"struct":[["ChannelReceiveFuture","A Future that is returned by the `receive` function on a channel. The future gets resolved with `Some(value)` when a value could be received from the channel. If the channels gets closed and no items are still enqueued inside the channel, the future will resolve to `None`."],["ChannelSendError","The error which is returned when sending a value into a channel fails."],["ChannelSendFuture","A Future that is returned by the `send` function on a channel. The future gets resolved with `None` when a value could be written to the channel. If the channel gets closed the send operation will fail, and the Future will resolve to `ChannelSendError(T)` and return the item to send."],["ChannelStream","A stream that receives from a `GenericChannel`."],["GenericChannel","A channel which can be used to exchange values of type `T` between concurrent tasks."],["GenericOneshotBroadcastChannel","A channel which can be used to exchange a single value between two or more concurrent tasks."],["GenericOneshotChannel","A channel which can be used to exchange a single value between two concurrent tasks."],["GenericStateBroadcastChannel","A channel which can be used to synchronize the state between a sender an arbitrary number of receivers."],["StateId","An ID, which allows to differentiate states received from a Channel. Elements with a bigger state ID (`id > otherId`) have been published more recently into the Channel."],["StateReceiveFuture","A Future that is returned by the `receive` function on a state broadcast channel. The future gets resolved with `Some((state_id, state))` when a value could be received from the channel."]],"type":[["Channel","A [`GenericChannel`] implementation backed by [`parking_lot`]."],["LocalChannel","A [`GenericChannel`] implementation which is not thread-safe."],["LocalOneshotBroadcastChannel","A [`GenericOneshotBroadcastChannel`] which is not thread-safe."],["LocalOneshotChannel","A [`GenericOneshotChannel`] which is not thread-safe."],["LocalStateBroadcastChannel","A [`GenericStateBroadcastChannel`] which is not thread-safe."],["LocalUnbufferedChannel","An unbuffered [`GenericChannel`] implementation which is not thread-safe."],["OneshotBroadcastChannel","A [`GenericOneshotBroadcastChannel`] implementation backed by [`parking_lot`]."],["OneshotChannel","A [`GenericOneshotChannel`] implementation backed by [`parking_lot`]."],["StateBroadcastChannel","A [`GenericStateBroadcastChannel`] implementation backed by [`parking_lot`]."],["UnbufferedChannel","An unbuffered [`GenericChannel`] implementation backed by [`parking_lot`]."]]};