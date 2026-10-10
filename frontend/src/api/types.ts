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

export type Metric = Series["metric"];
export type SeriesWindow = Series["window"];
