/** Frontmatter + `## section` markdown documents.
 *
 *  Contract: parse → mutate a known section → serialize must preserve every
 *  unknown section and the original section order (SPEC §4.3). Sections are
 *  addressed by heading text; the writer only ever replaces a section body or
 *  appends a new section at the end.
 */

import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';

export interface MdSection {
  heading: string;
  /** Body without the heading line, trailing blank lines stripped. */
  body: string;
}

export interface MdDoc {
  frontmatter: Record<string, unknown>;
  /** Text between the frontmatter and the first `## ` heading. */
  preamble: string;
  sections: MdSection[];
}

export class MdParseError extends Error {
  readonly file: string | undefined;

  constructor(message: string, file?: string) {
    super(file ? `${file}: ${message}` : message);
    this.name = 'MdParseError';
    this.file = file;
  }
}

const FM_OPEN = /^---\r?\n/;

function splitFrontmatter(text: string): { yaml: string; rest: string } {
  const normalized = text.startsWith('﻿') ? text.slice(1) : text;
  if (!FM_OPEN.test(normalized)) {
    return { yaml: '', rest: normalized };
  }
  const lines = normalized.split('\n');
  let end = -1;
  for (let i = 1; i < lines.length; i += 1) {
    const line = (lines[i] ?? '').replace(/\r$/, '');
    if (line === '---') {
      end = i;
      break;
    }
  }
  if (end === -1) throw new MdParseError('unclosed YAML frontmatter');
  return {
    yaml: lines.slice(1, end).join('\n'),
    rest: lines.slice(end + 1).join('\n'),
  };
}

export function parseMd(text: string, file?: string): MdDoc {
  let yamlText: string;
  let rest: string;
  try {
    const split = splitFrontmatter(text);
    yamlText = split.yaml;
    rest = split.rest;
  } catch (err) {
    throw new MdParseError(err instanceof Error ? err.message : String(err), file);
  }

  let frontmatter: Record<string, unknown> = {};
  if (yamlText.trim() !== '') {
    let parsed: unknown;
    try {
      parsed = parseYaml(yamlText);
    } catch (err) {
      throw new MdParseError(
        `invalid YAML frontmatter: ${err instanceof Error ? err.message : String(err)}`,
        file,
      );
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new MdParseError('frontmatter is not a YAML map', file);
    }
    frontmatter = parsed as Record<string, unknown>;
  }

  const lines = rest.split('\n');
  const sections: MdSection[] = [];
  const preambleLines: string[] = [];
  let current: { heading: string; body: string[] } | null = null;
  for (const raw of lines) {
    const line = raw.replace(/\r$/, '');
    const m = /^##\s+(.*)$/.exec(line);
    if (m) {
      if (current) sections.push({ heading: current.heading, body: trimBody(current.body) });
      current = { heading: (m[1] ?? '').trim(), body: [] };
      continue;
    }
    if (current) current.body.push(line);
    else preambleLines.push(line);
  }
  if (current) sections.push({ heading: current.heading, body: trimBody(current.body) });

  return { frontmatter, preamble: trimBody(preambleLines), sections };
}

function trimBody(lines: string[]): string {
  let start = 0;
  let end = lines.length;
  while (start < end && (lines[start] ?? '').trim() === '') start += 1;
  while (end > start && (lines[end - 1] ?? '').trim() === '') end -= 1;
  return lines.slice(start, end).join('\n');
}

export function serializeMd(doc: MdDoc): string {
  const out: string[] = [];
  out.push('---');
  const yaml = stringifyYaml(doc.frontmatter, { lineWidth: 0 }).replace(/\n$/, '');
  if (yaml !== '' && yaml !== '{}') out.push(yaml);
  out.push('---');
  if (doc.preamble.trim() !== '') {
    out.push(doc.preamble);
  }
  for (const s of doc.sections) {
    out.push('');
    out.push(`## ${s.heading}`);
    if (s.body.trim() !== '') out.push(s.body);
  }
  return `${out.join('\n').replace(/\n{3,}/g, '\n\n')}\n`;
}

/** Lines a section/comment/decision parser would read as structure
 *  (`## heading`, `### heading`, a log line, a plan step) get a leading
 *  backtick so free-form user text can never forge a section, a comment,
 *  a decision or a log entry on the next parse (S4, md/log injection). */
const HEADING_LINE = /^#{1,6}\s/;
const LOG_LINE = /^\s*-\s*\d{4}-\d{2}-\d{2} /;
const STEP_LINE = /^\s*- \[[ xX]\] /;

export function escapeStructuralLines(text: string): string {
  if (text === '') return text;
  return text
    .split('\n')
    .map((line) =>
      HEADING_LINE.test(line) || LOG_LINE.test(line) || STEP_LINE.test(line) ? `\`${line}` : line,
    )
    .join('\n');
}

export function getSection(doc: MdDoc, heading: string): MdSection | undefined {
  const want = heading.toLowerCase();
  return doc.sections.find((s) => s.heading.toLowerCase() === want);
}

/** Replace a section body in place, or append the section when missing. */
export function setSection(doc: MdDoc, heading: string, body: string): void {
  const existing = getSection(doc, heading);
  if (existing) {
    existing.body = body;
    return;
  }
  doc.sections.push({ heading, body });
}

/** Append lines to a section body (creates the section when missing). */
export function appendToSection(doc: MdDoc, heading: string, text: string): void {
  const existing = getSection(doc, heading);
  if (!existing) {
    doc.sections.push({ heading, body: text });
    return;
  }
  existing.body = existing.body.trim() === '' ? text : `${existing.body}\n${text}`;
}
