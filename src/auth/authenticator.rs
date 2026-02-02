use std::net::Ipv4Addr;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use smoltcp::wire::EthernetAddress;

use crate::config::POLL_TIMEOUT_MS;
use crate::credentials::Credentials;
use crate::error::AuthError;

use super::drcom_auth::DrcomAuth;
use super::eap_auth::{EapAuth, EapState};

pub struct Authenticator {
    eap: EapAuth,
    drcom: DrcomAuth,
    shutdown: Arc<AtomicBool>,
}

impl Authenticator {
    pub fn new(interface: &str, credentials: Credentials) -> Result<Self, AuthError> {
        let credentials = Rc::new(credentials);

        let eap = EapAuth::new(interface, Rc::clone(&credentials))?;

        let drcom = DrcomAuth::new(
            eap.local_ip(),
            eap.local_mac(),
            Rc::clone(&credentials),
        )?;

        Ok(Self {
            eap,
            drcom,
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn local_ip(&self) -> Ipv4Addr {
        self.eap.local_ip()
    }

    pub fn local_mac(&self) -> EthernetAddress {
        self.eap.local_mac()
    }

    pub fn logoff(&mut self) {
        self.eap.logoff();
    }

    fn setup_signal_handler(&self) {
        let shutdown_clone = self.shutdown.clone();
        ctrlc::set_handler(move || {
            log::info!("Received shutdown signal...");
            shutdown_clone.store(true, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
    }

    fn should_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Main authentication event loop.
    /// This is single-threaded and uses timeout-based polling for cross-platform compatibility.
    pub fn authenticate(&mut self) -> Result<(), AuthError> {
        // Start UDP keepalive
        self.drcom.start()?;

        // Set up shutdown signal handler
        self.setup_signal_handler();

        // Configure short timeouts for polling mode
        self.eap.set_timeout(POLL_TIMEOUT_MS)?;
        self.drcom.set_timeout(Duration::from_millis(POLL_TIMEOUT_MS))?;

        log::info!("Entering main event loop...");

        loop {
            // Check for shutdown signal
            if self.should_shutdown() {
                log::info!("Shutting down...");
                self.eap.logoff();
                return Ok(());
            }

            // EAP handles its own retry logic internally
            let eap_state = self.eap.tick()?;

            if eap_state != EapState::Authenticated {
                continue; // Skip DRCOM until EAP succeeds
            }

            // DRCOM handles its own heartbeat timing internally
            self.drcom.tick()?;
        }
    }
}
