// Notification Service
use reqwest::Client;
use serde_json::json;

pub async fn send_email(
    to: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Using SendGrid
    let client = Client::new();
    let sendgrid_key = std::env::var("SENDGRID_API_KEY")?;

    client
        .post("https://api.sendgrid.com/v3/mail/send")
        .header("Authorization", format!("Bearer {}", sendgrid_key))
        .json(&json!({
            "personalizations": [{
                "to": [{"email": to}],
                "subject": "Contract Dependency Updates Available"
            }],
            "from": {"email": "notifications@soroban-registry.com"},
            "content": [{
                "type": "text/html",
                "value": message
            }]
        }))
        .send()
        .await?;

    Ok(())
}

pub async fn send_webhook(
    url: &str,
    updates: &[UpdateInfo],
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    client
        .post(url)
        .json(&json!({
            "event": "dependency_updates",
            "updates": updates
        }))
        .send()
        .await?;

    Ok(())
}

fn format_notification_message(updates: &[UpdateInfo]) -> String {
    let mut html = String::from("<h1>Contract Dependency Updates</h1>");

    for update in updates {
        let security_badge = if update.is_security {
            "<span style='color: red; font-weight: bold;'>🔒 SECURITY UPDATE</span>"
        } else {
            ""
        };

        html.push_str(&format!(
            "<div style='margin: 20px 0; padding: 15px; border-left: 4px solid #0066cc;'>
                <h3>{} {}</h3>
                <p>Current: {} → Latest: {}</p>
                <p>Update Type: {:?}</p>
            </div>",
            update.contract_name,
            security_badge,
            update.current_version,
            update.latest_version,
            update.update_type
        ));
    }

    html
}