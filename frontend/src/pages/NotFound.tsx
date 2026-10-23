import { messages } from "../i18n/common.i18n";
import { Link } from "../lib/router";

export function NotFound() {
  return (
    <>
      <div className="page-head">
        <div>
          <h1>{messages("notFoundTitle")}</h1>
          <p>{messages("notFoundText")}</p>
        </div>
      </div>
      <Link className="btn" to="/">
        {messages("notFoundBack")}
      </Link>
    </>
  );
}
