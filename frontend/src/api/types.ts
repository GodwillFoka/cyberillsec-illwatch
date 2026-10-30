// Types de l'API, générés depuis le schéma OpenAPI de FastAPI (`npm run gen:api`, ADR-016).
// Aucun type d'échange n'est écrit à la main : si le serveur change, la compilation échoue.
import type { components } from "./schema";

type Schemas = components["schemas"];

export type TokenResponse = Schemas["TokenResponse"];
export type User = Schemas["UserRead"];
export type Summary = Schemas["SummaryRead"];
export type Series = Schemas["SeriesRead"];
export type Activity = Schemas["ActivityRead"];
export type FeedHealth = Schemas["FeedHealthRead"];
export type Alert = Schemas["AlertRead"];
export type AlertPage = Schemas["AlertPage"];
export type Incident = Schemas["IncidentRead"];
export type IncidentPage = Schemas["IncidentPage"];
export type IncidentDetail = Schemas["IncidentDetail"];
export type CveDetail = Schemas["CVEDetail"];
export type Cve = Schemas["CVERead"];
export type CvePage = Schemas["CVEPage"];
export type IncidentEvent = Schemas["EventRead"];
export type IndicatorDetail = Schemas["IndicatorDetail"];
export type Indicator = Schemas["IndicatorRead"];
export type IndicatorPage = Schemas["IndicatorPage"];
export type IngestResult = Schemas["IngestResponse"];
export type IncidentStatus = Incident["status"];
export type Severity = Incident["severity"];

export type HuntRule = Schemas["RuleRead"];
export type Hunt = Schemas["HuntRead"];
export type HuntDetail = Schemas["HuntDetail"];
export type HuntMatch = Schemas["MatchRead"];
export type HuntMatchPage = Schemas["MatchPage"];

export type Feed = Schemas["FeedRead"];
export type CollectionRun = Schemas["CollectionRunRead"];
export type Account = Schemas["AccountRead"];
export type AuditEvent = Schemas["AuditEventRead"];
export type AuditPage = Schemas["AuditPage"];
export type DemoRequest = Schemas["DemoRequestRead"];
export type DemoRequestPage = Schemas["DemoRequestPage"];
export type DemoRequestStatus = DemoRequest["status"];
export type SettingsInfo = Schemas["SettingsRead"];

export type Asset = Schemas["AssetRead"];
export type AssetWrite = Schemas["AssetWrite"];
export type AssetImport = Schemas["AssetImportRead"];
export type Correlation = Schemas["CorrelationRead"];
export type CorrelationPage = Schemas["CorrelationPage"];
export type CorrelationRun = Schemas["CorrelationRunRead"];

export type Exclusion = Schemas["ExclusionRead"];
export type SocMetrics = Schemas["SocMetricsRead"];
export type AlertQuality = Schemas["AlertQualityRead"];
export type QualityRow = Schemas["QualityRowRead"];
export type CatalogueFreshness = Schemas["CatalogueFreshnessRead"];
export type Recommendation = Schemas["RecommendationRead"];
export type IncidentHunt = Schemas["IncidentHuntRead"];
export type SocTier = Incident["tier"];
export type AttackContext = Schemas["AttackContextRead"];
export type TechniqueRef = Schemas["TechniqueRefRead"];
export type AttackStatus = Schemas["AttackStatusRead"];
export type Campaign = Schemas["CampaignRead"];
export type CampaignDetail = Schemas["CampaignDetail"];

export type Metric = Series["metric"];
export type SeriesWindow = Series["window"];
