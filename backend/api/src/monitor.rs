// Update Monitor - Checks for dependency updates
use sqlx::PgPool;
use semver::Version;

pub struct UpdateInfo {
    pub contract_name: String,
    pub current_version: String,
    pub latest_version: String,
    pub update_type: UpdateType,
    pub is_security: bool,
}

pub enum UpdateType {
    Patch,
    Minor,
    Major,
}

pub async fn check_for_updates(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Get all publishers with notifications enabled
    let publishers = sqlx::query!(
        "SELECT DISTINCT publisher_address, email, webhook_url, frequency, filter_level
         FROM notification_settings
         WHERE enabled = true"
    )
    .fetch_all(pool)
    .await?;

    for publisher in publishers {
        // 2. Get all contracts by this publisher
        let contracts = sqlx::query!(
            "SELECT name, version, dependencies
             FROM contracts
             WHERE publisher_address = $1
             ORDER BY name, published_at DESC",
            publisher.publisher_address
        )
        .fetch_all(pool)
        .await?;

        let mut updates = Vec::new();

        for contract in contracts {
            // 3. Parse dependencies
            let deps: Vec<Dependency> = serde_json::from_value(contract.dependencies)?;

            for dep in deps {
                // 4. Check if dependency has newer version
                if let Some(update) = check_dependency_update(pool, &dep).await? {
                    // 5. Filter by update level
                    if should_notify(&update, &publisher.filter_level) {
                        updates.push(update);
                    }
                }
            }
        }

        // 6. Send notification if updates found
        if !updates.empty() {
            send_notification(&publisher, updates).await?;
        }
    }

    Ok(())
}

async fn check_dependency_update(
    pool: &PgPool,
    dep: &Dependency,
) -> Result<Option<UpdateInfo>, Box<dyn std::error::Error>> {
    // Get latest version of dependency
    let latest = sqlx::query!(
        "SELECT version, is_security_update
         FROM contracts
         WHERE name = $1
         ORDER BY published_at DESC
         LIMIT 1",
        dep.name
    )
    .fetch_optional(pool)
    .await?;

    if let Some(latest_version) = latest {
        let current = Version::parse(&dep.version_requirement)?;
        let latest = Version::parse(&latest_version.version)?;

        if latest > current {
            let update_type = determine_update_type(&current, &latest);
            return Ok(Some(UpdateInfo {
                contract_name: dep.name.clone(),
                current_version: current.to_string(),
                latest_version: latest.to_string(),
                update_type,
                is_security: latest_version.is_security_update.unwrap_or(false),
            }));
        }
    }

    Ok(None)
}

fn determine_update_type(current: &Version, latest: &Version) -> UpdateType {
    if current.major != latest.major {
        UpdateType::Major
    } else if current.minor != latest.minor {
        UpdateType::Minor
    } else {
        UpdateType::Patch
    }
}

fn should_notify(update: &UpdateInfo, filter: &str) -> bool {
    match filter {
        "Security" => update.is_security,
        "Major" => matches!(update.update_type, UpdateType::Major),
        "Minor" => matches!(update.update_type, UpdateType::Minor | UpdateType::Major),
        "All" => true,
        _ => true,
    }
}

async fn send_notification(
    publisher: &PublisherSettings,
    updates: Vec<UpdateInfo>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Format notification message
    let message = format_notification_message(&updates);

    // Send email
    if !publisher.email.is_empty() {
        send_email(&publisher.email, &message).await?;
    }

    // Send webhook
    if let Some(webhook_url) = &publisher.webhook_url {
        send_webhook(webhook_url, &updates).await?;
    }

    Ok(())
}