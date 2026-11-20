"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { NetworkTabs } from "@/components/network-tabs";
import {
  Badge,
  Button,
  Card,
  ErrorState,
  Field,
  Input,
  Loading,
  PageHeader,
  Select,
  Table,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { type Credential, useCredentials } from "@/lib/network";
import { unwrap } from "@/lib/queries";

const AUTH = ["sha256", "sha", "sha224", "sha384", "sha512", "md5"];
const PRIV = ["aes", "aes192", "aes256", "aes192c", "aes256c", "des"];

function CredentialForm({ edit, onDone }: { edit?: Credential; onDone: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(edit?.name ?? "");
  const [version, setVersion] = useState(edit?.version ?? "2c");
  const [community, setCommunity] = useState("");
  const [username, setUsername] = useState(edit?.username ?? "");
  const [authProtocol, setAuthProtocol] = useState(edit?.auth_protocol ?? "sha256");
  const [authPassword, setAuthPassword] = useState("");
  const [privProtocol, setPrivProtocol] = useState(edit?.priv_protocol ?? "aes");
  const [privPassword, setPrivPassword] = useState("");
  const [tokenUser, setTokenUser] = useState(edit?.token_user ?? "");
  const [tokenName, setTokenName] = useState(edit?.token_name ?? "");
  const [tokenValue, setTokenValue] = useState("");
  const [insecure, setInsecure] = useState(edit?.insecure_tls ?? true);
  const [level, setLevel] = useState(
    edit
      ? edit.priv_protocol
        ? "authPriv"
        : edit.auth_protocol
          ? "authNoPriv"
          : "noAuthNoPriv"
      : "authPriv",
  );
  const body = {
    name,
    version: version as "1" | "2c" | "3" | "proxmox",
    community: version === "3" || version === "proxmox" ? null : community || null,
    token_user: version === "proxmox" ? tokenUser : null,
    token_name: version === "proxmox" ? tokenName : null,
    token_value: version === "proxmox" ? tokenValue || null : null,
    insecure_tls: version === "proxmox" ? insecure : null,
    username: version === "3" ? username : null,
    auth_protocol: version === "3" && level !== "noAuthNoPriv" ? authProtocol : null,
    auth_password: version === "3" && level !== "noAuthNoPriv" ? authPassword || null : null,
    priv_protocol: version === "3" && level === "authPriv" ? privProtocol : null,
    priv_password: version === "3" && level === "authPriv" ? privPassword || null : null,
  };
  const save = useMutation({
    mutationFn: async () =>
      edit
        ? unwrap(
            await api.PATCH("/v1/network/credentials/{credential_id}", {
              params: { path: { credential_id: edit.id } },
              body,
            }),
          )
        : unwrap(await api.POST("/v1/network/credentials", { body })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["network", "credentials"] });
      onDone();
    },
  });
  const keep = edit ? "Leave empty to keep the current one." : undefined;
  return (
    <form
      className="grid gap-4 sm:grid-cols-2"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      <Field label="Name" hint="For you: e.g. 'site1 switches'.">
        <Input value={name} onChange={(e) => setName(e.target.value)} required maxLength={100} />
      </Field>
      <Field label="SNMP version">
        <Select value={version} onChange={(e) => setVersion(e.target.value)}>
          <option value="2c">v2c (community)</option>
          <option value="3">v3 (user, authentication, encryption)</option>
          <option value="1">v1 (old devices only)</option>
          <option value="proxmox">Proxmox VE API token</option>
        </Select>
      </Field>
      {version === "proxmox" ? (
        <>
          <Field
            label="Token user"
            hint="Datacenter › Permissions › API Tokens; the PVEAuditor role is enough."
          >
            <Input
              value={tokenUser}
              onChange={(e) => setTokenUser(e.target.value)}
              placeholder="monitoring@pve"
              required
              maxLength={255}
            />
          </Field>
          <Field label="Token name">
            <Input
              value={tokenName}
              onChange={(e) => setTokenName(e.target.value)}
              placeholder="sentinel"
              required
              maxLength={255}
            />
          </Field>
          <Field label="Token secret" hint={keep ?? "Stored encrypted; never shown again."}>
            <Input
              type="password"
              autoComplete="off"
              value={tokenValue}
              onChange={(e) => setTokenValue(e.target.value)}
              required={!edit?.token_set}
              maxLength={255}
            />
          </Field>
          <label className="flex items-center gap-2 self-end pb-2 text-sm text-ink">
            <input
              type="checkbox"
              checked={insecure}
              onChange={(e) => setInsecure(e.target.checked)}
            />
            Accept a self-signed certificate (Proxmox&apos;s default)
          </label>
        </>
      ) : version !== "3" ? (
        <Field label="Community" hint={keep ?? "Read-only. Stored encrypted; never shown again."}>
          <Input
            type="password"
            autoComplete="off"
            value={community}
            onChange={(e) => setCommunity(e.target.value)}
            required={!edit}
            maxLength={255}
          />
        </Field>
      ) : (
        <>
          <Field label="Username">
            <Input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              maxLength={255}
            />
          </Field>
          <Field label="Security level">
            <Select value={level} onChange={(e) => setLevel(e.target.value)}>
              <option value="authPriv">Authentication and encryption (recommended)</option>
              <option value="authNoPriv">Authentication only</option>
              <option value="noAuthNoPriv">Neither</option>
            </Select>
          </Field>
          {level !== "noAuthNoPriv" && (
            <>
              <Field label="Authentication">
                <Select value={authProtocol} onChange={(e) => setAuthProtocol(e.target.value)}>
                  {AUTH.map((a) => (
                    <option key={a} value={a}>
                      {a.toUpperCase()}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Authentication password" hint={keep ?? "At least 8 characters."}>
                <Input
                  type="password"
                  autoComplete="off"
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                  required={!edit?.auth_set}
                  maxLength={255}
                />
              </Field>
            </>
          )}
          {level === "authPriv" && (
            <>
              <Field
                label="Encryption"
                hint="aes256c is the Cisco/Reeder key extension (FortiGate calls it aes256cisco)."
              >
                <Select value={privProtocol} onChange={(e) => setPrivProtocol(e.target.value)}>
                  {PRIV.map((p) => (
                    <option key={p} value={p}>
                      {p.toUpperCase()}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Encryption password" hint={keep ?? "At least 8 characters."}>
                <Input
                  type="password"
                  autoComplete="off"
                  value={privPassword}
                  onChange={(e) => setPrivPassword(e.target.value)}
                  required={!edit?.priv_set}
                  maxLength={255}
                />
              </Field>
            </>
          )}
        </>
      )}
      <div className="flex flex-wrap items-center gap-3 sm:col-span-2">
        <Button type="submit" variant="primary" loading={save.isPending}>
          {edit ? "Save" : "Add credential"}
        </Button>
        <Button type="button" onClick={onDone}>
          Cancel
        </Button>
        {save.error && <span className="text-sm text-bad">{errorText(save.error)}</span>}
      </div>
    </form>
  );
}

export default function CredentialsPage() {
  const qc = useQueryClient();
  const creds = useCredentials();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Credential | null>(null);
  const remove = useMutation({
    mutationFn: async (id: string) =>
      unwrap(
        await api.DELETE("/v1/network/credentials/{credential_id}", {
          params: { path: { credential_id: id } },
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["network", "credentials"] }),
  });
  if (creds.isLoading) return <Loading />;
  if (creds.error)
    return <ErrorState message={errorText(creds.error)} retry={() => creds.refetch()} />;
  return (
    <>
      <PageHeader
        title="Network"
        subtitle="SNMP credentials, shared by the devices that use them"
        actions={
          !adding &&
          !editing && (
            <Button variant="primary" onClick={() => setAdding(true)}>
              Add credential
            </Button>
          )
        }
      />
      <NetworkTabs />
      {(adding || editing) && (
        <div className="mb-6">
          <Card title={editing ? `Edit ${editing.name}` : "Add credential"}>
            <CredentialForm
              key={editing?.id ?? "new"}
              edit={editing ?? undefined}
              onDone={() => {
                setAdding(false);
                setEditing(null);
              }}
            />
          </Card>
        </div>
      )}
      <Card pad={false}>
        <Table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Version</th>
              <th>Details</th>
              <th>Devices</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {creds.data!.map((c) => (
              <tr key={c.id}>
                <td className="font-medium">{c.name}</td>
                <td>
                  <Badge>{c.version === "proxmox" ? "Proxmox" : `v${c.version}`}</Badge>
                </td>
                <td className="text-ink-2">
                  {c.version === "proxmox"
                    ? `${c.token_user}!${c.token_name}${c.insecure_tls ? " · self-signed OK" : ""}`
                    : c.version === "3"
                      ? `${c.username} · ${c.auth_protocol ? c.auth_protocol.toUpperCase() : "no auth"}${c.priv_protocol ? ` + ${c.priv_protocol.toUpperCase()}` : ""}`
                      : c.community_set
                        ? "community set"
                        : "no community"}
                </td>
                <td className="tabular">{c.devices}</td>
                <td className="text-right whitespace-nowrap">
                  <Button variant="ghost" onClick={() => setEditing(c)}>
                    Edit
                  </Button>
                  <Button
                    variant="ghost"
                    disabled={c.devices > 0}
                    title={c.devices > 0 ? "Devices use it" : undefined}
                    onClick={() => window.confirm(`Delete ${c.name}?`) && remove.mutate(c.id)}
                  >
                    Delete
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
        {!creds.data!.length && (
          <p className="p-5 text-sm text-ink-3">
            No credentials yet. Add the read-only community (v2c) or SNMPv3 user your devices use.
          </p>
        )}
        {remove.error && <p className="p-3 text-sm text-bad">{errorText(remove.error)}</p>}
      </Card>
    </>
  );
}
