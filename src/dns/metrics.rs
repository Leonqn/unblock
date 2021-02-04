use std::net::IpAddr;

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

pub struct PerIpCounter {
    counter: IntCounterVec,
}

impl PerIpCounter {
    pub fn new(metric_name: &str) -> Self {
        Self {
            counter: register_int_counter_vec!(metric_name, metric_name, &["ip"]).unwrap(),
        }
    }

    pub fn inc(&self, ip: IpAddr) {
        let ip = ip.to_string().replace('.', "_");
        self.counter.with_label_values(&[&ip]).inc()
    }
}
