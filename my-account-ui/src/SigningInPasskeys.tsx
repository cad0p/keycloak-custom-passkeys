import {
  Button,
  DataList,
  DataListAction,
  DataListCell,
  DataListItem,
  DataListItemCells,
  DataListItemRow,
  Dropdown,
  DropdownItem,
  MenuToggle,
  PageSection,
  Spinner,
  Split,
  SplitItem,
  Title,
  TextInput,
} from "@patternfly/react-core";
import { EllipsisVIcon, PencilAltIcon, CheckIcon, TimesIcon } from "@patternfly/react-icons";
import { CSSProperties, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useEnvironment } from "@keycloak/keycloak-account-ui";
import { getCredentials } from "@keycloak/keycloak-account-ui";
import {
  CredentialContainer,
  CredentialMetadataRepresentation,
} from "@keycloak/keycloak-account-ui";
import { EmptyRow } from "@keycloak/keycloak-account-ui";
import { Page } from "@keycloak/keycloak-account-ui";
import { TFuncKey } from "./i18n";
import { formatDate } from "./utils/formatDate";
import { usePromise } from "@keycloak/keycloak-account-ui";
import React from "react";

type MobileLinkProps = {
  title: string;
  onClick: () => void;
  testid?: string;
};

const MobileLink = ({ title, onClick, testid }: MobileLinkProps) => {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Dropdown
        popperProps={{
          position: "right",
        }}
        onOpenChange={(isOpen) => setOpen(isOpen)}
        toggle={(toggleRef) => (
          <MenuToggle
            className="pf-v5-u-display-none-on-lg"
            ref={toggleRef}
            variant="plain"
            onClick={() => setOpen(!open)}
            isExpanded={open}
          >
            <EllipsisVIcon />
          </MenuToggle>
        )}
        isOpen={open}
      >
        <DropdownItem key="1" onClick={onClick}>
          {title}
        </DropdownItem>
      </Dropdown>
      <Button
        variant="link"
        onClick={onClick}
        className="pf-v5-u-display-none pf-v5-u-display-inline-flex-on-lg"
        data-testid={testid}
      >
        {title}
      </Button>
    </>
  );
};

export const SigningIn = () => {
  const { t } = useTranslation();
  const context = useEnvironment();
  const { login } = context.keycloak;

  const [credentials, setCredentials] = useState<CredentialContainer[]>();
  const [editingCredentialId, setEditingCredentialId] = useState<string>();
  const [newLabel, setNewLabel] = useState<string>("");

  usePromise(
    async (signal) => {
      const creds = await getCredentials({ signal, context });
      console.log('Raw credentials:', creds);
      
      // Merge duplicate entries instead of filtering them out
      const mergedCreds = creds.reduce((acc, current) => {
        const existingIndex = acc.findIndex(item => 
          item.category === current.category && 
          item.type === current.type &&
          item.userCredentialMetadatas.some(meta => 
            current.userCredentialMetadatas.some(currentMeta => 
              currentMeta.credential.id === meta.credential.id
            )
          )
        );

        if (existingIndex === -1) {
          acc.push(current);
        } else {
          // Merge properties, preferring non-null values
          acc[existingIndex] = {
            ...acc[existingIndex],
            ...current,
            createAction: acc[existingIndex].createAction || current.createAction,
            updateAction: acc[existingIndex].updateAction || current.updateAction,
          };
        }
        return acc;
      }, [] as CredentialContainer[]);

      return mergedCreds;
    },
    setCredentials,
    [],
  );

  const handleUpdateLabel = async (credentialId: string, newLabel: string) => {
    try {
      throw new Error('Not implemented');
    } catch (error) {
      console.error('Failed to update label:', error);
    } finally {
      setEditingCredentialId(undefined); // Clear editing state regardless of success/failure
    }
  };

  const credentialRowCells = (
    credMetadata: CredentialMetadataRepresentation,
  ) => {
    const credential = credMetadata.credential;
    const maxWidth = {
      "--pf-v5-u-max-width--MaxWidth": "300px",
    } as CSSProperties;
    const items = [
      <DataListCell
        key="title"
        data-testrole="label"
        className="pf-v5-u-max-width"
        style={maxWidth}
      >
        {editingCredentialId === credential.id ? (
          <TextInput
            value={newLabel}
            onChange={(_event, value) => setNewLabel(value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                handleUpdateLabel(credential.id, newLabel);
              } else if (e.key === 'Escape') {
                setEditingCredentialId(undefined);
              }
            }}
            autoFocus
          />
        ) : (
          t(credential.userLabel) || t(credential.type as TFuncKey)
        )}
      </DataListCell>,
    ];

    if (credential.createdDate) {
      items.push(
        <DataListCell
          key={"created" + credential.id}
          data-testrole="created-at"
        >
          <Trans i18nKey="credentialCreatedAt">
            <strong className="pf-v5-u-mr-md"></strong>
            {{ date: formatDate(new Date(credential.createdDate)) }}
          </Trans>
        </DataListCell>,
      );
    }
    return items;
  };

  if (!credentials) {
    return <Spinner />;
  }

  const credentialUniqueCategories = [
    ...new Set(credentials.map((c) => c.category)),
  ];

  return (
    <Page title={t("signingIn")} description={t("signingInDescription")}>
      {credentialUniqueCategories.map((category) => (
        <PageSection key={category} variant="light" className="pf-v5-u-px-0">
          <Title headingLevel="h2" size="xl" id={`${category}-categ-title`}>
            {t(category as TFuncKey)}
          </Title>
          {credentials
            .filter((cred) => cred.category == category)
            .map((container) => (
              <>
                <Split className="pf-v5-u-mt-lg pf-v5-u-mb-lg">
                  <SplitItem>
                    <Title
                      headingLevel="h3"
                      size="md"
                      className="pf-v5-u-mb-md"
                      data-testid={`${container.type}/help`}
                    >
                      <span
                        className="cred-title pf-v5-u-display-block"
                        data-testid={`${container.type}/title`}
                      >
                        {t(container.displayName as TFuncKey)}
                      </span>
                    </Title>
                    <span data-testid={`${container.type}/help-text`}>
                      {t(container.helptext as TFuncKey)}
                    </span>
                  </SplitItem>
                  {container.createAction && (
                    <SplitItem isFilled>
                      <div className="pf-v5-u-float-right">
                        <MobileLink
                          onClick={() =>
                            login({
                              action: container.createAction,
                            })
                          }
                          title={t("setUpNew", {
                            name: t(
                              `${container.type}-display-name` as TFuncKey,
                            ),
                          })}
                          testid={`${container.type}/create`}
                        />
                      </div>
                    </SplitItem>
                  )}
                </Split>

                <DataList
                  aria-label="credential list"
                  className="pf-v5-u-mb-xl"
                  data-testid={`${container.type}/credential-list`}
                >
                  {container.userCredentialMetadatas.length === 0 && (
                    <EmptyRow
                      message={t("notSetUp", {
                        name: t(container.displayName as TFuncKey),
                      })}
                      data-testid={`${container.type}/not-set-up`}
                    />
                  )}

                  {container.userCredentialMetadatas.map((meta) => (
                    <DataListItem key={meta.credential.id}>
                      <DataListItemRow id={`cred-${meta.credential.id}`}>
                        <DataListItemCells
                          className="pf-v5-u-py-0"
                          dataListCells={[
                            ...credentialRowCells(meta),
                            <DataListAction
                              key="action"
                              id={`action-${meta.credential.id}`}
                              aria-label={t("updateCredAriaLabel")}
                              aria-labelledby={`cred-${meta.credential.id}`}
                            >
                              {editingCredentialId === meta.credential.id ? (
                                <Button
                                  variant="plain"
                                  onClick={() => handleUpdateLabel(meta.credential.id, newLabel)}
                                  aria-label="Confirm"
                                  data-testrole="confirm-edit"
                                >
                                  <CheckIcon />
                                </Button>
                              ) : (
                                <Button
                                  variant="plain"
                                  onClick={() => {
                                    setEditingCredentialId(meta.credential.id);
                                    setNewLabel(meta.credential.userLabel || '');
                                  }}
                                  data-testrole="edit-label"
                                >
                                  <PencilAltIcon />
                                </Button>
                              )}
                              {editingCredentialId === meta.credential.id && (
                                <Button
                                  variant="plain"
                                  onClick={() => setEditingCredentialId(undefined)}
                                  aria-label="Cancel"
                                  data-testrole="cancel-edit"
                                >
                                  <TimesIcon />
                                </Button>
                              )}
                              {container.removeable && (
                                <Button
                                  variant="danger"
                                  data-testrole="remove"
                                  onClick={() => {
                                    login({
                                      action: "delete_credential:" + meta.credential.id,
                                    });
                                  }}
                                >
                                  {t("delete")}
                                </Button>
                              )}
                              {container.updateAction && !editingCredentialId && (
                                <Button
                                  variant="secondary"
                                  onClick={() => {
                                    login({ action: container.updateAction });
                                  }}
                                  data-testrole="update"
                                >
                                  {t("update")}
                                </Button>
                              )}
                            </DataListAction>,
                          ]}
                        />
                      </DataListItemRow>
                    </DataListItem>
                  ))}
                </DataList>
              </>
            ))}
        </PageSection>
      ))}
    </Page>
  );
};

export default SigningIn;
