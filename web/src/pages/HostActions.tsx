import { useQuery } from "@tanstack/react-query";
import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate } from "react-router";
import {
  api,
  queryKeys,
  type CommandRequest,
  type CommandType,
  type DefenderParams,
  type Host,
} from "../api";
import { ActionConfirmDialog } from "../components/ActionDialog";
import { ArtifactParamsForm } from "../components/ArtifactParams";
import { useCan } from "../components/Auth";
import { Icon, type IconName } from "../components/Icon";
import { EmptyState, ErrorState, Loading } from "../components/States";
import {
  artifactDefaults,
  artifactsForPlatform,
  normalizeArtifactParams,
  validateArtifactParams,
} from "../lib/artifacts";
import { actionAllowed, COMMAND_LABEL } from "../lib/commands";
import { splitList } from "../lib/format";

function ActionCard({
  icon,
  title,
  description,
  type,
  host,
  children,
}: {
  icon: IconName;
  title: string;
  description: ReactNode;
  type: CommandType | CommandType[];
  host: Host;
  children: ReactNode;
}) {
  const types = Array.isArray(type) ? type : [type];
  const blocked = types.filter((t) => !actionAllowed(host, t));
  return (
    <section className="panel">
      <div className="panel-header">
        <h2 className="row" style={{ gap: 8 }}>
          <Icon name={icon} size={15} /> {title}
        </h2>
        <span className="mono xsmall faint">{types.join(" · ")}</span>
      </div>
      <div className="panel-body stack" style={{ gap: 10 }}>
        <p className="muted small" style={{ margin: 0 }}>
          {description}
        </p>
        {blocked.length === types.length ? (
          <div className="callout warn">
            <Icon name="warning" size={14} />
            <span>
              {types.map((t) => COMMAND_LABEL[t]).join(" / ")}{" "}
              {types.length > 1 ? "are" : "is"} not allowed by this agent’s
              local policy (<span className="mono">allowed_actions</span>).
              Change it in the agent’s config file on the host.
            </span>
          </div>
        ) : (
          children
        )}
      </div>
    </section>
  );
}

const PATH_HINT = {
  windows: "C:\\Users\\alex\\Downloads\\file.exe",
  linux: "/tmp/file",
  darwin: "/Users/alex/Downloads/file",
  network: "",
};

export function HostActions({ host }: { host: Host }) {
  const canAct = useCan("analyst");
  const isAdmin = useCan("admin");
  const navigate = useNavigate();
  const [request, setRequest] = useState<CommandRequest | null>(null);

  // form state
  const [allow, setAllow] = useState("");
  const [pid, setPid] = useState("");
  const [entity, setEntity] = useState("");
  const [tree, setTree] = useState(false);
  const [qPath, setQPath] = useState("");
  const [restoreId, setRestoreId] = useState("");
  const [getPath, setGetPath] = useState("");
  const [maxMiB, setMaxMiB] = useState("");
  const [hashPath, setHashPath] = useState("");

  if (!canAct) {
    return (
      <div className="panel">
        <EmptyState title="Response actions need the analyst role">
          Your account is read-only.
        </EmptyState>
      </div>
    );
  }
  if (host.kind === "network") {
    return (
      <div className="panel">
        <EmptyState title="No response actions for network devices">
          {host.hostname} is a syslog source. Actions run only on hosts with the
          HomeXDR agent.
        </EmptyState>
      </div>
    );
  }
  if (host.status === "revoked") {
    return (
      <div className="panel">
        <EmptyState title="This agent is revoked">
          It can no longer receive commands.
        </EmptyState>
      </div>
    );
  }

  const pathHint = PATH_HINT[host.os.platform] ?? "";
  const pidNum = Number(pid);
  const pidValid = /^\d+$/.test(pid) && pidNum > 0;
  const done = () =>
    navigate(`/hosts/${encodeURIComponent(host.id)}?tab=commands`);

  return (
    <div className="stack">
      {host.status === "offline" ? (
        <div className="callout warn">
          <Icon name="warning" size={14} />
          <span>
            {host.hostname} is offline. Commands are queued and delivered when
            it reconnects, unless they expire first (1 hour).
          </span>
        </div>
      ) : null}
      <div className="grid grid-2" style={{ alignItems: "start" }}>
        <ActionCard
          icon={host.isolated ? "release" : "isolate"}
          title={host.isolated ? "Host is isolated" : "Network isolation"}
          type={host.isolated ? "host.release" : "host.isolate"}
          host={host}
          description={
            host.isolated
              ? "All traffic except the HomeXDR server, loopback, DHCP and DNS is blocked. Release the host to restore normal access."
              : "Cut the host off from the network while you investigate. The server connection, loopback, DHCP and DNS always stay open, so it can be released."
          }
        >
          {host.isolated ? (
            <div>
              <button
                type="button"
                className="btn"
                onClick={() => setRequest({ type: "host.release", params: {} })}
              >
                <Icon name="release" size={14} /> Release host…
              </button>
            </div>
          ) : (
            <form
              className="stack"
              style={{ gap: 8 }}
              onSubmit={(e: FormEvent) => {
                e.preventDefault();
                const list = splitList(allow);
                setRequest({
                  type: "host.isolate",
                  params: list.length ? { allow: list } : {},
                });
              }}
            >
              <div className="field">
                <label htmlFor="iso-allow">Also allow (optional)</label>
                <input
                  id="iso-allow"
                  className="input mono"
                  placeholder="192.168.1.10, 10.0.0.0/24"
                  value={allow}
                  onChange={(e) => setAllow(e.target.value)}
                />
                <span className="help">
                  IP addresses or CIDRs, comma separated, e.g. your admin
                  workstation.
                </span>
              </div>
              <div>
                <button type="submit" className="btn danger">
                  <Icon name="isolate" size={14} /> Isolate host…
                </button>
              </div>
            </form>
          )}
        </ActionCard>

        <ActionCard
          icon="kill"
          title="Kill process"
          type="process.kill"
          host={host}
          description="Terminate a process by PID. Add the process entity ID (from an event or the process tree) so a reused PID is never hit."
        >
          <form
            className="stack"
            style={{ gap: 8 }}
            onSubmit={(e) => {
              e.preventDefault();
              if (pidValid)
                setRequest({
                  type: "process.kill",
                  params: {
                    pid: pidNum,
                    entity_id: entity.trim() || undefined,
                    tree,
                  },
                });
            }}
          >
            <div className="row" style={{ alignItems: "flex-start" }}>
              <div className="field" style={{ width: 120 }}>
                <label htmlFor="kill-pid">PID</label>
                <input
                  id="kill-pid"
                  className={
                    pid && !pidValid ? "input mono invalid" : "input mono"
                  }
                  inputMode="numeric"
                  value={pid}
                  onChange={(e) => setPid(e.target.value.trim())}
                />
              </div>
              <div className="field grow">
                <label htmlFor="kill-entity">Entity ID (recommended)</label>
                <input
                  id="kill-entity"
                  className="input mono"
                  value={entity}
                  onChange={(e) => setEntity(e.target.value)}
                  placeholder="process.entity_id"
                />
              </div>
            </div>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={tree}
                onChange={(e) => setTree(e.target.checked)}
              />{" "}
              Also kill child processes
            </label>
            <div>
              <button type="submit" className="btn danger" disabled={!pidValid}>
                <Icon name="kill" size={14} /> Kill process…
              </button>
            </div>
          </form>
        </ActionCard>

        <ActionCard
          icon="quarantine"
          title="Quarantine / restore file"
          type={["file.quarantine", "file.restore"]}
          host={host}
          description="Move a file into the agent's quarantine folder so it cannot run. Restore uses the quarantine ID from the quarantine command's output."
        >
          <form
            className="row"
            style={{ alignItems: "flex-end" }}
            onSubmit={(e) => {
              e.preventDefault();
              if (qPath.trim())
                setRequest({
                  type: "file.quarantine",
                  params: { path: qPath.trim() },
                });
            }}
          >
            <div className="field grow">
              <label htmlFor="q-path">File path</label>
              <input
                id="q-path"
                className="input mono"
                placeholder={pathHint}
                value={qPath}
                onChange={(e) => setQPath(e.target.value)}
              />
            </div>
            <button
              type="submit"
              className="btn danger"
              disabled={
                !qPath.trim() || !actionAllowed(host, "file.quarantine")
              }
            >
              Quarantine…
            </button>
          </form>
          <form
            className="row"
            style={{ alignItems: "flex-end" }}
            onSubmit={(e) => {
              e.preventDefault();
              if (restoreId.trim())
                setRequest({
                  type: "file.restore",
                  params: { id: restoreId.trim() },
                });
            }}
          >
            <div className="field grow">
              <label htmlFor="r-id">Quarantine ID</label>
              <input
                id="r-id"
                className="input mono"
                value={restoreId}
                onChange={(e) => setRestoreId(e.target.value)}
              />
            </div>
            <button
              type="submit"
              className="btn"
              disabled={
                !restoreId.trim() || !actionAllowed(host, "file.restore")
              }
            >
              Restore…
            </button>
          </form>
        </ActionCard>

        {isAdmin ? (
          <ActionCard
            icon="download"
            title="Get file"
            type="file.get"
            host={host}
            description="Upload a copy of a file from the host to the server for analysis. The original is not changed."
          >
            <form
              className="row"
              style={{ alignItems: "flex-end" }}
              onSubmit={(e) => {
                e.preventDefault();
                const mb = Number(maxMiB);
                if (getPath.trim())
                  setRequest({
                    type: "file.get",
                    params: {
                      path: getPath.trim(),
                      max_bytes:
                        maxMiB && mb > 0
                          ? Math.round(mb * 1024 * 1024)
                          : undefined,
                    },
                  });
              }}
            >
              <div className="field grow">
                <label htmlFor="g-path">File path</label>
                <input
                  id="g-path"
                  className="input mono"
                  placeholder={pathHint}
                  value={getPath}
                  onChange={(e) => setGetPath(e.target.value)}
                />
              </div>
              <div className="field" style={{ width: 110 }}>
                <label htmlFor="g-max">Max MiB</label>
                <input
                  id="g-max"
                  className="input"
                  inputMode="decimal"
                  placeholder="100"
                  value={maxMiB}
                  onChange={(e) => setMaxMiB(e.target.value)}
                />
              </div>
              <button type="submit" className="btn" disabled={!getPath.trim()}>
                Get file…
              </button>
            </form>
          </ActionCard>
        ) : null}

        <ActionCard
          icon="hash"
          title="Hash file"
          type="file.hash"
          host={host}
          description="Compute MD5, SHA-1 and SHA-256 of a file on the host, e.g. to look it up in threat intel."
        >
          <form
            className="row"
            style={{ alignItems: "flex-end" }}
            onSubmit={(e) => {
              e.preventDefault();
              if (hashPath.trim())
                setRequest({
                  type: "file.hash",
                  params: { path: hashPath.trim() },
                });
            }}
          >
            <div className="field grow">
              <label htmlFor="h-path">File path</label>
              <input
                id="h-path"
                className="input mono"
                placeholder={pathHint}
                value={hashPath}
                onChange={(e) => setHashPath(e.target.value)}
              />
            </div>
            <button type="submit" className="btn" disabled={!hashPath.trim()}>
              Hash file…
            </button>
          </form>
        </ActionCard>

        <ArtifactCard host={host} onRequest={setRequest} />
        {host.os.platform === "windows" ? (
          <DefenderCard host={host} onRequest={setRequest} />
        ) : null}
      </div>
      <ActionConfirmDialog
        host={host}
        request={request}
        onClose={() => setRequest(null)}
        onDone={done}
      />
    </div>
  );
}

function DefenderCard({
  host,
  onRequest,
}: {
  host: Host;
  onRequest: (r: CommandRequest) => void;
}) {
  const [threat, setThreat] = useState("");
  const [scanPath, setScanPath] = useState("");
  const id = Number(threat);
  const idValid = /^\d+$/.test(threat) && id > 0;
  const d = (params: DefenderParams) =>
    onRequest({ type: "defender.action", params });
  return (
    <ActionCard
      icon="bug"
      title="Microsoft Defender"
      type="defender.action"
      host={host}
      description="Drive Defender on this PC: status, scans, signature updates, and what Defender does with a threat it detected. The threat ID is in the Defender alert's data (Threat ID)."
    >
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <button
          type="button"
          className="btn"
          onClick={() => d({ action: "status" })}
        >
          Status…
        </button>
        <button
          type="button"
          className="btn"
          onClick={() => d({ action: "scan", scan_type: "quick" })}
        >
          Quick scan…
        </button>
        <button
          type="button"
          className="btn"
          onClick={() => d({ action: "scan", scan_type: "full" })}
        >
          Full scan…
        </button>
        <button
          type="button"
          className="btn"
          onClick={() => d({ action: "update" })}
        >
          Update signatures…
        </button>
        <button
          type="button"
          className="btn danger"
          onClick={() => d({ action: "remove_threats" })}
        >
          Remove active threats…
        </button>
      </div>
      <form
        className="row"
        style={{ alignItems: "flex-end" }}
        onSubmit={(e) => {
          e.preventDefault();
          if (scanPath.trim())
            d({ action: "scan", scan_type: "path", path: scanPath.trim() });
        }}
      >
        <div className="field grow">
          <label htmlFor="d-path">Scan one file</label>
          <input
            id="d-path"
            className="input mono"
            placeholder={PATH_HINT.windows}
            value={scanPath}
            onChange={(e) => setScanPath(e.target.value)}
          />
        </div>
        <button type="submit" className="btn" disabled={!scanPath.trim()}>
          Scan file…
        </button>
      </form>
      <div className="row" style={{ alignItems: "flex-end" }}>
        <div className="field grow">
          <label htmlFor="d-threat">Threat ID</label>
          <input
            id="d-threat"
            className="input mono"
            inputMode="numeric"
            placeholder="2147519003"
            value={threat}
            onChange={(e) => setThreat(e.target.value.trim())}
          />
        </div>
        <button
          type="button"
          className="btn"
          disabled={!idValid}
          onClick={() => d({ action: "allow_threat", threat_id: id })}
          title="False positive: allow it and restore it from quarantine"
        >
          Allow…
        </button>
        <button
          type="button"
          className="btn"
          disabled={!idValid}
          onClick={() => d({ action: "block_threat", threat_id: id })}
          title="Undo an allow"
        >
          Block…
        </button>
      </div>
    </ActionCard>
  );
}

function ArtifactCard({
  host,
  onRequest,
}: {
  host: Host;
  onRequest: (r: CommandRequest) => void;
}) {
  const q = useQuery({
    queryKey: queryKeys.artifacts,
    queryFn: api.listArtifacts,
    staleTime: Infinity,
  });
  const defs = useMemo(
    () => artifactsForPlatform(q.data?.artifacts ?? [], host.os.platform),
    [q.data, host.os.platform],
  );
  const [name, setName] = useState("");
  const def = defs.find((d) => d.name === name) ?? defs[0];
  const [values, setValues] = useState<Record<string, string>>({});
  const [touched, setTouched] = useState(false);
  const current = def ? { ...artifactDefaults(def), ...values } : {};
  const errors = def ? validateArtifactParams(def, current) : {};

  return (
    <ActionCard
      icon="artifact"
      title="Run artifact"
      type="artifact.collect"
      host={host}
      description="Run one of the built-in, read-only collectors and view its rows under Commands."
    >
      {q.isPending ? (
        <Loading compact />
      ) : q.isError ? (
        <ErrorState error={q.error} compact onRetry={() => q.refetch()} />
      ) : !def ? (
        <EmptyState title={`No artifacts for ${host.os.platform}`} compact />
      ) : (
        <form
          className="stack"
          style={{ gap: 10 }}
          onSubmit={(e) => {
            e.preventDefault();
            setTouched(true);
            if (Object.keys(errors).length) return;
            const params = normalizeArtifactParams(def, current);
            onRequest({
              type: "artifact.collect",
              params: Object.keys(params).length
                ? { name: def.name, params }
                : { name: def.name },
            });
          }}
        >
          <div className="field">
            <label htmlFor="art-name">Artifact</label>
            <select
              id="art-name"
              className="select"
              value={def.name}
              onChange={(e) => {
                setName(e.target.value);
                setValues({});
                setTouched(false);
              }}
            >
              {defs.map((d) => (
                <option key={d.name} value={d.name}>
                  {d.name}
                </option>
              ))}
            </select>
            <span className="help">{def.description}</span>
          </div>
          <ArtifactParamsForm
            def={def}
            values={current}
            onChange={setValues}
            errors={touched ? errors : {}}
          />
          <div className="xsmall muted">
            Columns: <span className="mono">{def.columns.join(", ")}</span>
          </div>
          <div>
            <button type="submit" className="btn primary">
              <Icon name="play" size={12} /> Run {def.name}…
            </button>
          </div>
        </form>
      )}
    </ActionCard>
  );
}
