use std::sync::Arc;

use arc_swap::ArcSwapOption;
use log::{info, warn};
use tokio_stream::{Stream, StreamExt};

pub struct LastItem<T> {
    item: Arc<ArcSwapOption<T>>,
}

impl<T: Send + Sync + 'static> LastItem<T> {
    pub fn new(stream: impl Stream<Item = T> + Send + 'static) -> Self {
        let mut stream = Box::pin(stream);
        let item = Arc::new(ArcSwapOption::empty());
        let updater = {
            let item = item.clone();
            async move {
                while let Some(stream_item) = stream.next().await {
                    info!("Got new item");
                    item.store(Some(Arc::new(stream_item)));
                }
                warn!("Updater exited")
            }
        };
        tokio::spawn(updater);
        Self { item }
    }

    pub fn item(&self) -> Option<Arc<T>> {
        self.item.load_full()
    }
}
