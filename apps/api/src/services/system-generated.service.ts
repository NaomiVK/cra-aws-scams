import { Injectable, Logger } from '@nestjs/common';
import { SearchAnalyticsRow } from '@cra-scam-detection/shared-types';
import { SystemGeneratedQuery } from '@cra-scam-detection/shared-types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Headline verb pattern — present tense 3rd-person verbs in headline style (EN + FR)
 */
const HEADLINE_VERB_PATTERN = new RegExp(
  '\\b(' +
  // English
  'begins|improves|revamped|receives?|starts|approaches|promises|expects|announces|introduces|launches|offers|provides|updates|expands|extends|delivers|confirms|warns|reports|plans|prepares|aims|seeks|faces|enters|opens|closes|ends|continues|remains|includes|features|highlights|ensures|enables|allows|supports|covers|targets|affects|impacts|addresses|reveals|unveils|utilize|reduces?|increases?|decreases?|advises?|recommends?|suggests?|indicates?|specifies|requires?|applies|determines?|explains?' +
  '|' +
  // French
  'commence|améliore|reçoivent|annonce|lance|offre|propose|prévoit|confirme|prépare|entre|ouvre|ferme|continue|inclut|permet|assure|vise|présente|introduit|prolonge|élargit|étend|fournit|soutient|dévoile|révèle|publie|conseille|recommande|rappelle|suggère|indique|précise|débutent?|modifie|augmente|diminue|réduit|exige|détermine|applique|explique|maintient|ajoute|supprime|remplace|établit|accorde|priorise' +
  ')\\b',
  'i'
);

/**
 * Formal headline vocabulary — words rarely used in search queries (EN + FR)
 */
const FORMAL_VOCABULARY_PATTERN = new RegExp(
  '\\b(' +
  // English
  'eligible|various|upcoming|promising|anticipated|expected|revised|updated|enhanced|streamlined|designated|scheduled|allocated|announced|effective|applicable|pursuant|regarding|utilize|deductions?|furthermore|whereas|hereby|accordingly|notwithstanding|respectively|wherein|thereof' +
  '|' +
  // French
  'admissibles?|divers|prochaine?|promettant|anticipée?|prévu|révisée?|améliorée?|désignée?|annoncée?|applicable|conformément|concernant|attendu|différentes?|précipiter|régimes?|selon|également|toutefois|notamment|néanmoins|davantage|dorénavant' +
  ')\\b',
  'i'
);

/**
 * Temporal headline markers — date references in headline style (EN + FR)
 */
const TEMPORAL_MARKER_PATTERN = new RegExp(
  '\\b(' +
  // English
  'today|tomorrow|monday|tuesday|wednesday|thursday|friday|this week|this month|next month' +
  '|in (?:january|february|march|april|may|june|july|august|september|october|november|december) \\d{4}' +
  '|' +
  // French
  "aujourd'hui|demain|lundi|mardi|mercredi|jeudi|vendredi|cette semaine|ce mois|le mois prochain" +
  '|en (?:janvier|février|mars|avril|mai|juin|juillet|août|septembre|octobre|novembre|décembre) \\d{4}' +
  ')\\b',
  'i'
);

/**
 * Headline punctuation — commas, semicolons, colons almost never used in search queries
 */
const HEADLINE_PUNCTUATION_PATTERN = /[;:,]/;

/**
 * Function words — articles, prepositions, pronouns, particles that appear in
 * natural language sentences but rarely in keyword-style search queries.
 */
const FUNCTION_WORDS_EN = new Set([
  'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
  'to', 'for', 'of', 'in', 'on', 'by', 'with', 'at', 'from', 'into',
  'not', 'do', 'does', 'did', 'can', 'could', 'will', 'would', 'shall',
  'should', 'may', 'might', 'must', 'have', 'has', 'had',
  'their', 'your', 'its', 'our', 'my', 'his', 'her',
  'that', 'which', 'who', 'whom', 'whose', 'this', 'these', 'those',
  'and', 'or', 'but', 'if', 'than', 'because', 'while', 'although',
  'it', 'they', 'we', 'he', 'she', 'you', 'i',
]);

const FUNCTION_WORDS_FR = new Set([
  'le', 'la', 'les', 'un', 'une', 'des', 'du', 'au', 'aux',
  'de', 'ne', 'pas', 'se', 'pour', 'par', 'avec', 'dans', 'en', 'sur',
  'votre', 'vos', 'leur', 'leurs', 'notre', 'nos', 'mon', 'ma', 'mes', 'son', 'sa', 'ses',
  'qui', 'que', 'ce', 'cette', 'ces', 'dont', 'où',
  'et', 'ou', 'mais', 'si', 'car', 'ni',
  'il', 'elle', 'ils', 'elles', 'on', 'nous', 'vous', 'je', 'tu',
  'est', 'sont', 'être', 'avoir', 'ont', 'peut', 'peuvent', 'doit', 'doivent',
]);

const ALL_FUNCTION_WORDS = new Set([...FUNCTION_WORDS_EN, ...FUNCTION_WORDS_FR]);

/**
 * Function word density threshold — queries above this ratio are likely sentences
 */
const FUNCTION_WORD_DENSITY_THRESHOLD = 0.35;

/**
 * Question words — queries starting with these are likely real user searches.
 * Exempt from detection unless they exceed the longer word threshold.
 */
const QUESTION_WORD_PATTERN = /^(what|when|why)\b/i;
const QUESTION_QUERY_MIN_WORDS = 10;

/**
 * Minimum word count for system-generated detection
 */
const MIN_WORD_COUNT = 6;

@Injectable()
export class SystemGeneratedService {
  private readonly logger = new Logger(SystemGeneratedService.name);

  /**
   * Detect system-generated (AI Overview) queries from search analytics data.
   *
   * A query is flagged if it meets: length threshold (6+ words) AND at least 1 structural signal.
   */
  detectSystemGeneratedQueries(rows: SearchAnalyticsRow[]): SystemGeneratedQuery[] {
    const results: SystemGeneratedQuery[] = [];

    for (const row of rows) {
      const query = row.keys[0]?.toLowerCase() || '';
      const signals = this.checkSignals(query);

      // Must have structural signals AND low CTR (<5%) — high-CTR matches are likely real searches
      if (signals.length > 0 && row.ctr < 0.05) {
        results.push({
          id: uuidv4(),
          query,
          impressions: row.impressions,
          clicks: row.clicks,
          ctr: row.ctr,
          position: row.position,
          matchedSignals: signals,
        });
      }
    }

    // Sort by impressions descending
    results.sort((a, b) => b.impressions - a.impressions);

    this.logger.log(
      `[SYSTEM_GENERATED] Detected ${results.length} system-generated queries from ${rows.length} rows`
    );

    return results;
  }

  /**
   * Check if a single query matches system-generated signals.
   * Returns the list of matched signal names (empty = not system-generated).
   */
  isSystemGenerated(query: string): boolean {
    return this.checkSignals(query.toLowerCase()).length > 0;
  }

  /**
   * Check all structural signals for a query.
   * Returns matched signal names. Empty array = not system-generated.
   */
  private checkSignals(query: string): string[] {
    const words = query.split(/\s+/).filter(w => w.length > 0);
    const wordCount = words.length;

    // Length gate: must be 6+ words
    if (wordCount < MIN_WORD_COUNT) {
      return [];
    }

    // Question queries (what, when, how, etc.) are likely real user searches
    // Only flag them if they're 10+ words (long enough to be AI-generated)
    if (QUESTION_WORD_PATTERN.test(query) && wordCount < QUESTION_QUERY_MIN_WORDS) {
      return [];
    }

    const signals: string[] = [];

    if (HEADLINE_VERB_PATTERN.test(query)) {
      signals.push('headline_verb');
    }

    if (FORMAL_VOCABULARY_PATTERN.test(query)) {
      signals.push('formal_vocabulary');
    }

    if (TEMPORAL_MARKER_PATTERN.test(query)) {
      signals.push('temporal_marker');
    }

    if (HEADLINE_PUNCTUATION_PATTERN.test(query)) {
      signals.push('headline_punctuation');
    }

    // Function word density — high ratio of function words indicates a natural language sentence
    const functionWordCount = this.countFunctionWords(words);
    const density = functionWordCount / wordCount;
    if (density >= FUNCTION_WORD_DENSITY_THRESHOLD) {
      signals.push('sentence_structure');
    }

    return signals;
  }

  /**
   * Count function words in a tokenized query.
   * Handles French contractions (l', d', n', s', j', qu') by splitting them.
   */
  private countFunctionWords(words: string[]): number {
    let count = 0;

    for (const word of words) {
      // Handle French contractions: l'arc -> l' + arc, d'impôts -> d' + impôts
      const contractionMatch = word.match(/^(l|d|n|s|j|qu)'(.+)$/i);
      if (contractionMatch) {
        // The contraction prefix (l', d', etc.) is always a function word
        count++;
        // Check if the remaining part is also a function word
        if (ALL_FUNCTION_WORDS.has(contractionMatch[2])) {
          count++;
        }
        continue;
      }

      // Strip trailing punctuation for matching
      const clean = word.replace(/[.,;:!?]$/, '');
      if (ALL_FUNCTION_WORDS.has(clean)) {
        count++;
      }
    }

    return count;
  }
}
