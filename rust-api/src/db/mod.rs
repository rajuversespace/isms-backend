use bson::doc;
use mongodb::{Client, Database, IndexModel};

/// Connect to MongoDB and return a handle to the specified database.
pub async fn connect(uri: &str, database_name: &str) -> Result<Database, mongodb::error::Error> {
    let client = Client::with_uri_str(uri).await?;

    // Verify connectivity with a ping
    client
        .database("admin")
        .run_command(doc! { "ping": 1 })
        .await?;

    Ok(client.database(database_name))
}

/// Create required indexes on all collections.
/// Called once at startup.
pub async fn create_indexes(db: &Database) -> Result<(), mongodb::error::Error> {
    // Users collection
    let users = db.collection::<bson::Document>("users");
    users
        .create_index(
            IndexModel::builder()
                .keys(doc! { "email": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .unique(true)
                        .build(),
                )
                .build(),
        )
        .await?;
    users
        .create_index(IndexModel::builder().keys(doc! { "org_id": 1 }).build())
        .await?;

    // Organizations collection
    let orgs = db.collection::<bson::Document>("organizations");
    orgs.create_index(
        IndexModel::builder()
            .keys(doc! { "name": 1 })
            .options(
                mongodb::options::IndexOptions::builder()
                    .unique(true)
                    .build(),
            )
            .build(),
    )
    .await?;

    // Frameworks collection
    let frameworks = db.collection::<bson::Document>("frameworks");
    frameworks
        .create_index(IndexModel::builder().keys(doc! { "org_id": 1 }).build())
        .await?;
    frameworks
        .create_index(
            IndexModel::builder()
                .keys(doc! { "vanta_id": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .sparse(true)
                        .build(),
                )
                .build(),
        )
        .await?;

    // Controls collection
    let controls = db.collection::<bson::Document>("controls");
    controls
        .create_index(IndexModel::builder().keys(doc! { "org_id": 1 }).build())
        .await?;
    controls
        .create_index(
            IndexModel::builder()
                .keys(doc! { "framework_id": 1 })
                .build(),
        )
        .await?;
    controls
        .create_index(
            IndexModel::builder()
                .keys(doc! { "org_id": 1, "code": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .unique(true)
                        .build(),
                )
                .build(),
        )
        .await?;

    // Policies collection
    let policies = db.collection::<bson::Document>("policies");
    policies
        .create_index(IndexModel::builder().keys(doc! { "org_id": 1 }).build())
        .await?;

    // Audits collection
    let audits = db.collection::<bson::Document>("audits");
    audits
        .create_index(IndexModel::builder().keys(doc! { "org_id": 1 }).build())
        .await?;

    // Findings collection
    let findings = db.collection::<bson::Document>("findings");
    findings
        .create_index(IndexModel::builder().keys(doc! { "org_id": 1 }).build())
        .await?;
    findings
        .create_index(IndexModel::builder().keys(doc! { "audit_id": 1 }).build())
        .await?;

    // Assets collection
    let assets = db.collection::<bson::Document>("assets");
    assets
        .create_index(IndexModel::builder().keys(doc! { "org_id": 1 }).build())
        .await?;

    // Risks collection
    let risks = db.collection::<bson::Document>("risks");
    risks
        .create_index(IndexModel::builder().keys(doc! { "org_id": 1 }).build())
        .await?;

    // Evidence collection
    let evidence = db.collection::<bson::Document>("evidence");
    evidence
        .create_index(IndexModel::builder().keys(doc! { "org_id": 1 }).build())
        .await?;
    evidence
        .create_index(IndexModel::builder().keys(doc! { "control_id": 1 }).build())
        .await?;

    // Activity logs collection
    let activity_logs = db.collection::<bson::Document>("activity_logs");
    activity_logs
        .create_index(
            IndexModel::builder()
                .keys(doc! { "org_id": 1, "created_at": -1 })
                .build(),
        )
        .await?;

    tracing::debug!("All database indexes created successfully");
    Ok(())
}
