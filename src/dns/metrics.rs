use prometheus::{register_int_counter_vec, IntCounterVec};

pub struct PerDomainCounter {
    counter: IntCounterVec,
}

impl PerDomainCounter {
    pub fn new(metric_name: &str) -> Self {
        Self {
            counter: register_int_counter_vec!(metric_name, metric_name, &["domain"]).unwrap(),
        }
    }

    pub fn inc(&self, domain: &str) {
        let domain = domain.replace('.', "_");
        self.counter.with_label_values(&[&domain]).inc()
    }
}
