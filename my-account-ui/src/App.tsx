import { Page, PageSection, PageSectionVariants, Spinner } from "@patternfly/react-core";
import style from "./App.module.css";

import { Header } from "@keycloak/keycloak-account-ui";
import { Suspense } from "react";
import { Outlet } from "react-router-dom";
import { PageNav } from "./PageNav";
import React from "react";

function App() {
  return (
    <Page className={style.headerLogo} header={<Header />} sidebar={<PageNav />} isManagedSidebar>
      <Suspense fallback={<Spinner />}>
        <Outlet />
      </Suspense>
    </Page>
  );
}

export default App;
