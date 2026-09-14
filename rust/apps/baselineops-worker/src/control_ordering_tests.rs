use super::*;

struct BarrierTransport {
    inner: Transport,
    release: mpsc::SyncSender<()>,
    ready: Receiver<()>,
}

impl ControlTransport for BarrierTransport {
    fn receive(&mut self, _timeout: Duration) -> Result<Option<BrokerMessage>> {
        panic!("barrier makes the result ready before the first receive");
    }
    fn send(&mut self, message: &BrokerMessage, timeout: Duration) -> Result<()> {
        self.inner.send(message, timeout)?;
        if self.inner.sent.len() == 5 {
            self.release.send(()).unwrap();
            self.ready.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        Ok(())
    }
}

#[test]
fn progress_arriving_after_the_initial_drain_is_forwarded_before_result() {
    let (mut inner, approval, results) = fixture();
    let result_tx = inner.result_sender.take().unwrap();
    let result = inner.result.take().unwrap();
    let (progress_tx, progress) = mpsc::sync_channel(4);
    let action_id = baselineops_domain::ActionId::new();
    for _ in 0..4 {
        progress_tx
            .send(NativeActionProgress {
                action_id,
                phase: NativeActionPhase::Started,
            })
            .unwrap();
    }
    let (release, released) = mpsc::sync_channel(0);
    let (ready_tx, ready) = mpsc::channel();
    let mut transport = BarrierTransport {
        inner,
        release,
        ready,
    };
    std::thread::scope(|scope| {
        scope.spawn(move || {
            released.recv_timeout(Duration::from_secs(2)).unwrap();
            progress_tx
                .send(NativeActionProgress {
                    action_id,
                    phase: NativeActionPhase::Finished,
                })
                .unwrap();
            result_tx.send(Ok(result)).unwrap();
            ready_tx.send(()).unwrap();
        });
        run(
            &mut transport,
            &approval,
            &CancellationToken::default(),
            &results,
            &progress,
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
    });
    let last: WorkerProgress =
        serde_json::from_value(transport.inner.sent.last().unwrap().payload.clone()).unwrap();
    assert_eq!(last.phase, ProgressPhase::ActionFinished);
    assert_eq!(transport.inner.sent.len(), 6);
}
