use std::time::{
    Duration,
    Instant,
};

use futures::TryStreamExt;
use goose::{
    metrics::{
        GooseMetric,
        GooseRawRequest,
        GooseRequestMetric,
    },
    prelude::*,
};
use rand::{
    distributions::Alphanumeric,
    Rng,
};

use iota_streams::{
    app::message::GenericMessage,
    app_channels::{
        Address,
        Author,
        ChannelType,
        MessageContent,
        Subscriber,
        Tangle as Client,
    },
    core_edsig::signature::ed25519::Keypair,
};

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        // In this example, we only create a single scenario, named "WebsiteUser".
        .register_scenario(
            scenario!("Load Testing Hornet node with Streams")
                // After each transactions runs, sleep randomly from 5 to 15 seconds.
                // .set_wait_time(Duration::from_secs(5), Duration::from_secs(15))?
                // This transaction only runs one time when the user first starts.
                .register_transaction(
                    transaction!(setup_author)
                        .set_on_start()
                        .set_name("Send announcement and keyload")
                        .set_sequence(1),
                )
                // These next two transactions run repeatedly as long as the load test is running.
                .register_transaction(
                    transaction!(publish_signed_packet)
                        .set_name("publish signed packet")
                        .set_sequence(2),
                )
                .register_transaction(
                    transaction!(read_signed_packet)
                        .set_name("read signed packet")
                        .set_sequence(3),
                ),
        )
        .execute()
        .await?;

    Ok(())
}

/// Demonstrates how to log in when a user starts. We flag this transaction as an
/// on_start transaction when registering it above. This means it only runs one time
/// per user, when the user thread first starts.
async fn setup_author(user: &mut GooseUser) -> TransactionResult {
    let author_seed: String = rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let node_url = user.base_url.as_str().to_string();
    let mut author = Author::new(&author_seed, ChannelType::SingleBranch, Client::new_from_url(&node_url));
    let req_start = Instant::now();
    let announcement = author.send_announce().await.expect("error sending announcement");
    let mut req_duration = req_start.elapsed();
    if let Some(parent) = user.channel_to_parent.clone() {
        parent.send(GooseMetric::Request(GooseRequestMetric {
            elapsed: user.started.elapsed().as_millis() as u64,
            raw: GooseRawRequest {
                method: GooseMethod::Post,
                url: format!("{} [send announcement]", node_url),
                headers: vec![],
                body: "".to_string(),
            },
            name: "send announcement".to_string(),
            final_url: format!("{} [send announcement]", node_url),
            response_time: req_duration.as_millis() as u64,
            status_code: 200,
            success: true,
            redirected: false,
            update: false,
            user: user.weighted_users_index,
            error: "".to_string(),
            coordinated_omission_elapsed: 0,
            user_cadence: 0,
        }))?;
    }
    let subscriber_seed: String = rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let mut subscriber = Subscriber::new(&subscriber_seed, Client::new_from_url(&node_url));
    let req_start = Instant::now();
    subscriber.receive_announcement(&announcement).await.unwrap();
    if let Some(parent) = user.channel_to_parent.clone() {
        parent.send(GooseMetric::Request(GooseRequestMetric {
            elapsed: user.started.elapsed().as_millis() as u64,
            raw: GooseRawRequest {
                method: GooseMethod::Get,
                url: format!("{} [read announcement]", node_url),
                headers: vec![],
                body: "".to_string(),
            },
            name: "read announcement".to_string(),
            final_url: format!("{} [read announcement]", node_url),
            response_time: req_start.elapsed().as_millis() as u64,
            status_code: 200,
            success: true,
            redirected: false,
            update: false,
            user: user.weighted_users_index,
            error: "".to_string(),
            coordinated_omission_elapsed: 0,
            user_cadence: 0,
        }))?;
    }

    author.store_new_subscriber(*subscriber.get_public_key()).unwrap();
    // for i in 0..100 {
    //     let kp = Keypair::generate(&mut rand::thread_rng());
    //     author
    //         .store_new_subscriber(kp.public)
    //         .expect(&format!("error storing subscriber {}", i));
    // }
    let req_start = Instant::now();
    let (keyload, _) = author
        .send_keyload_for_everyone(&announcement)
        .await
        .expect("error sending keyload");
    let req_duration = req_start.elapsed();
    if let Some(parent) = user.channel_to_parent.clone() {
        parent.send(GooseMetric::Request(GooseRequestMetric {
            elapsed: user.started.elapsed().as_millis() as u64,
            raw: GooseRawRequest {
                method: GooseMethod::Post,
                url: format!("{} [send keyload]", node_url),
                headers: vec![],
                body: "".to_string(),
            },
            name: "send keyload".to_string(),
            final_url: format!("{} [send keyload]", node_url),
            response_time: req_duration.as_millis() as u64,
            status_code: 200,
            success: true,
            redirected: false,
            update: false,
            user: user.weighted_users_index,
            error: "".to_string(),
            coordinated_omission_elapsed: 0,
            user_cadence: 0,
        }))?;
    }

    let req_start = Instant::now();
    assert!(subscriber.receive_keyload(&keyload).await.unwrap());
    if let Some(parent) = user.channel_to_parent.clone() {
        parent.send(GooseMetric::Request(GooseRequestMetric {
            elapsed: user.started.elapsed().as_millis() as u64,
            raw: GooseRawRequest {
                method: GooseMethod::Get,
                url: format!("{} [read keyload]", node_url),
                headers: vec![],
                body: "".to_string(),
            },
            name: "read keyload".to_string(),
            final_url: format!("{} [read keyload]", node_url),
            response_time: req_start.elapsed().as_millis() as u64,
            status_code: 200,
            success: true,
            redirected: false,
            update: false,
            user: user.weighted_users_index,
            error: "".to_string(),
            coordinated_omission_elapsed: 0,
            user_cadence: 0,
        }))?;
    }
    let mut payload = [0_u8; 1024];
    rand::thread_rng().fill(&mut payload);
    user.set_session_data((author, subscriber, keyload, payload));

    Ok(())
}
async fn publish_signed_packet(user: &mut GooseUser) -> TransactionResult {
    let (author, _, last_msg, payload): &mut (Author<Client>, Subscriber<Client>, Address, [u8; 1024]) =
        user.get_session_data_mut().expect("error finding setup data");
    let payload = *payload;
    let req_start = Instant::now();
    let result = author
        .send_signed_packet(last_msg, &payload.as_slice().into(), &[].into())
        .await;
    let req_duration = req_start.elapsed();

    match result {
        Ok((address, _)) => {
            *last_msg = address;
            if let Some(parent) = user.channel_to_parent.clone() {
                let node_url = user.base_url.as_str().to_string();
                parent.send(GooseMetric::Request(GooseRequestMetric {
                    elapsed: user.started.elapsed().as_millis() as u64,
                    raw: GooseRawRequest {
                        method: GooseMethod::Post,
                        url: format!("{} [send signed-packet]", node_url),
                        headers: vec![],
                        body: format!("{:x?}", payload),
                    },
                    name: "send signed-packet".to_string(),
                    final_url: format!("{} [send signed-packet]", node_url),
                    response_time: req_duration.as_millis() as u64,
                    status_code: 200,
                    success: true,
                    redirected: false,
                    update: false,
                    user: user.weighted_users_index,
                    error: "".to_string(),
                    coordinated_omission_elapsed: 0,
                    user_cadence: 0,
                }))?;
            }
        }
        Err(e) => {
            if let Some(parent) = user.channel_to_parent.clone() {
                let node_url = user.base_url.as_str().to_string();
                parent.send(GooseMetric::Request(GooseRequestMetric {
                    elapsed: user.started.elapsed().as_millis() as u64,
                    raw: GooseRawRequest {
                        method: GooseMethod::Post,
                        url: format!("{} [send signed-packet]", node_url),
                        headers: vec![],
                        body: format!("{:x?}", payload),
                    },
                    name: "send signed-packet".to_string(),
                    final_url: format!("{} [send signed-packet]", node_url),
                    response_time: req_duration.as_millis() as u64,
                    status_code: 400,
                    success: false,
                    redirected: false,
                    update: false,
                    user: user.weighted_users_index,
                    error: e.to_string(),
                    coordinated_omission_elapsed: 0,
                    user_cadence: 0,
                }))?;
            }
        }
    }
    Ok(())
}

async fn read_signed_packet(user: &mut GooseUser) -> TransactionResult {
    let (_, subscriber, keyload, payload): &mut (Author<Client>, Subscriber<Client>, Address, [u8; 1024]) =
        user.get_session_data_mut().expect("error finding setup data");
    let req_start = Instant::now();
    let message = subscriber
        .messages()
        .try_next()
        .await
        .expect("error reading signed packet");
    let req_duration = req_start.elapsed();
    let node_url = user.base_url.as_str().to_string();
    if matches!(
        message,
        Some(GenericMessage {
            body: MessageContent::SignedPacket { .. },
            ..
        })
    ) {
        if let Some(parent) = user.channel_to_parent.clone() {
            parent.send(GooseMetric::Request(GooseRequestMetric {
                elapsed: user.started.elapsed().as_millis() as u64,
                raw: GooseRawRequest {
                    method: GooseMethod::Get,
                    url: format!("{} [read signed-packet]", node_url),
                    headers: vec![],
                    body: "".to_string(),
                },
                name: "read signed-packet".to_string(),
                final_url: format!("{} [read signed-packet]", node_url),
                response_time: req_duration.as_millis() as u64,
                status_code: 200,
                success: true,
                redirected: false,
                update: false,
                user: user.weighted_users_index,
                error: "".to_string(),
                coordinated_omission_elapsed: 0,
                user_cadence: 0,
            }))?;
        }
    } else {
        if let Some(parent) = user.channel_to_parent.clone() {
            parent.send(GooseMetric::Request(GooseRequestMetric {
                elapsed: user.started.elapsed().as_millis() as u64,
                raw: GooseRawRequest {
                    method: GooseMethod::Get,
                    url: format!("{} [read signed-packet]", node_url),
                    headers: vec![],
                    body: "".to_string(),
                },
                name: "read signed-packet".to_string(),
                final_url: format!("{} [read signed-packet]", node_url),
                response_time: req_duration.as_millis() as u64,
                status_code: 404,
                success: false,
                redirected: false,
                update: false,
                user: user.weighted_users_index,
                error: "".to_string(),
                coordinated_omission_elapsed: 0,
                user_cadence: 0,
            }))?;
        }
    }

    Ok(())
}
