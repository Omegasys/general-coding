Dual-Script Writing Manual

A practical guide to reading and writing the language

Document status: Working specification, version 0.1
Purpose: Establish a consistent, learnable method for writing the
language in both its artistic and utilitarian scripts.
Important: The language and scripts are still being designed. Where
a rule has not yet been decided, this manual labels it as
provisional rather than pretending it is already final. The
descriptions below define how to use the system at this stage; final
glyph artwork, the final modifier-to-meaning mapping, and some grammar
details remain to be approved.

────────

1. The central idea

This language has one language and two scripts:

1. Artistic script — flowing, graceful, expressive, and suitable
for literature, poetry, reflection, inscriptions, and personal
writing.
2. Utilitarian script — angular, compact, consistent, and
suitable for everyday notes, technical documentation, scientific
work, contracts, and digital text.

The scripts represent the same words and grammatical information. They
do not have separate vocabularies, pronunciations, or grammars. A
sentence written in one script must be convertible to the other without
changing its meaning.

The artistic script may use composition, spacing, and optional color to
emphasize expression. The utilitarian script prioritizes consistency and
explicitness. Neither script is inherently more correct, intelligent,
sacred, or authoritative than the other.

Three writing modes

The scripts can be used in three modes:

• Everyday mode: ordinary communication; context can resolve
normal conversational ambiguity.
• Expressive mode: especially suited to the artistic script; uses
deliberate visual emphasis, rhythm, metaphor, and composition.
• Precision mode: either script can use it. Where ambiguity could
matter, the writer explicitly marks the relevant reference, time,
relationship, negation, or uncertainty.

Precision mode is a way of writing, not a third script.

────────

2. What is settled and what is provisional

Established design commitments

• There are exactly 28 base letters: five vowels and 23
consonants.
• Both scripts encode the same 28 letters.
• The default word order is subject–verb–object (SVO).
• The intended sound is balanced: neither exclusively soft and flowing
nor exclusively harsh and forceful.
• The language should be approachable to speakers from different
backgrounds and should not require knowledge of a fictional culture.
• Both scripts support a shared family of modifiers.
• Modifier meanings must remain consistent across both scripts.
• The artistic script uses flowing and curved forms; the utilitarian
script uses angular and grid-based forms.
• The five vowels have a proposed philosophical association with
AEIOU and the idea “I am who I am.” This is a symbolic design
choice, not a claim about the historical derivation of Hebrew or any
other language.

Provisional decisions in this manual

The following are practical working rules, not irreversible canon:

• The Latin-letter transliteration and phoneme inventory in Section 4.
• Left-to-right writing and top-to-bottom line order.
• Penultimate stress.
• The syllable template and restrictions.
• The modifier meanings and their written positions.
• Punctuation and numeral conventions.
• The exact grammatical particles and example word forms.

The language designer should revise this document when any of these
decisions are confirmed or changed. Do not treat an illustrative example
as an approved dictionary entry unless it is separately recorded in the
vocabulary.

────────

3. The two scripts at a glance

────────

Feature                 Artistic script         Utilitarian script

────────

Main visual language    Curves, arcs, loops,    Lines, angles, notches,
balanced open forms     modular forms

Character construction  Flowing strokes with    Consistent strokes on a
varied proportions      shared grid

Letter connections      Visual flow is allowed; Letters remain visually
joining is not required independent

Spacing                 May vary for deliberate Standardized and
composition within      consistent
readability limits

Modifiers               May follow the contours Occupy fixed,
of the glyph within     standardized positions
defined limits

Color                   Optional expressive or  Optional; never needed
decorative layer        to distinguish meaning

Handwriting             Calligraphic or         Quick, reproducible
simplified forms        strokes

Digital use             Must preserve text      Optimized for typing, identity and support    search, small screens, conversion              and technical text

Shared visual identity

The two scripts should share recognizable design features. These may
include a recurring notch, a distinctive dot arrangement, or a
characteristic open-ended stroke. The artistic script renders such
features organically; the utilitarian script renders them geometrically.

This shared visual DNA should make the scripts look related without
making their letters identical.

────────

4. The 28-letter inventory

The following is the current proposed pronunciation and Latin
transliteration. The actual native glyphs have not yet been finalized.
KH and Ñ each represent one base letter, even though KH uses two
Latin characters in this transliteration.

Vowels: 5

Transliteration   Proposed IPA   Approximate pronunciation

────────

A                 /a/            “a” as in father, without an English diphthong
E                 /e/            Pure vowel similar to Spanish e
I                 /i/            “ee” as in machine
O                 /o/            Pure vowel similar to Spanish o
U                 /u/            “oo” as in rule, without an English glide

Keep the vowels pure and short in the initial design. Do not
automatically turn E into the vowel of English they, or O into the
vowel of English go.

The vowel sequence AEIOU has a proposed symbolic reading:

• AE — being associated with the past.
• I — identity and present being.
• OU — being associated with the future.
• AEIOU as a whole — a philosophical emblem of “I am who I am.”

This symbolic interpretation does not mean that AE, I, or OU
automatically function as ordinary tense morphemes in every word.
Everyday tense must be expressed by the grammar once its markers are
finalized.

Consonants: 23

Group          Transliteration        Proposed IPA

────────

Stops          P, B, T, D, K, G, Q    /p b t d k g q/
Nasals         M, N, Ñ                /m n ɲ/
Fricatives     F, V, S, Z, X, H, KH   /f v s z ʃ h x/
Affricates     C, J                   /t͡ʃ d͡ʒ/
Approximants   L, R, W, Y             /l ɾ w j/

Pronunciation notes:

• Q /q/ is a voiceless uvular stop, made farther back in the mouth
than K. If this distinction proves too difficult for the intended
audience, it may be revised before the alphabet is finalized.
• Ñ /ɲ/ resembles the consonant represented by ñ in Spanish
señor.
• X /ʃ/ is the “sh” sound in English ship.
• KH /x/ is a voiceless velar or uvular fricative, similar to the
sound in some pronunciations of Scottish loch or German Bach.
• C /t͡ʃ/ is the “ch” sound in English church.
• J /d͡ʒ/ is the “j” sound in English judge.
• R /ɾ/ is a brief tap, similar to the single r in many
pronunciations of Spanish pero.
• Y /j/ is the consonant at the beginning of English yes.
• W /w/ is the consonant at the beginning of English water.

The romanization is a practical teaching notation, not a requirement
that native script glyphs resemble Latin letters. The native glyph for
KH is one character, not K followed by H. The same applies to every
other base letter: one inventory entry corresponds to one native glyph.

Transliteration rules

When typing the provisional Latin transliteration:

• Write the 28 letters using the labels in the tables above.
• Use uppercase letters in alphabet charts and examples; ordinary text
may use lowercase if the project later adopts case conventions.
• Treat KH as one letter when counting, sorting, or parsing the
language.
• Treat Ñ as a single letter.
• Do not use English spelling rules to infer pronunciation.
• Keep transliteration consistent; do not alternate between X and SH,
C and CH, or KH and a single improvised symbol.

A formal machine-readable transliteration standard should later define
normalization, sorting, case behavior, and how users type the two
multi-character labels.

────────

5. How to construct the artistic script

5.1 Overall appearance

The artistic script is built primarily from:

• Arcs and sweeping curves.
• Open and closed loops.
• Semicircles and rounded geometric forms.
• Deliberate dots and short strokes.
• Balanced asymmetry and varied proportions.
• Negative space that helps identify each letter.

Do not make every letter a circle or spiral. Each letter needs a
distinct silhouette. Curves are the shared design language, not a
substitute for differentiating the alphabet.

5.2 Handwriting procedure

For a typical handwritten glyph:

1. Draw the main body of the letter.
2. Add the secondary curve or structural stroke.
3. Add any required modifier marks.
4. Move to the next letter with a natural visual rhythm, without
merging the two glyphs into an ambiguous form.

This is a general construction order. The final alphabet chart must give
the exact stroke order for each individual glyph.

5.3 Letter joining

Letters do not have to connect physically. The script should look
flowing through repeated curves, aligned strokes, and rhythm rather than
requiring cursive joins.

If a formal calligrapher uses a flourish between letters, that flourish
must be decorative and must not be mistaken for a letter or modifier.

5.4 Proportions and spacing

Use a shared invisible writing zone:

• Most letters occupy a common body height.
• Some letters may rise above or descend below the body zone when
their design requires it.
• Dots and modifiers need reserved space so they do not collide with
adjacent glyphs.
• Word boundaries must remain obvious.
• A decorative flourish must never make a letter appear to belong to
the neighboring word.

Formal writing may vary letter widths and line spacing for composition.
Everyday handwriting should use simplified, repeatable forms.

5.5 Artistic levels

• Everyday hand: simplified glyphs, normal spacing, few
flourishes.
• Literary hand: balanced lines, intentional spacing, and
expressive emphasis.
• Formal calligraphy: elaborate but legible forms for poetry,
inscriptions, ceremonial documents, or display.

Color is optional. Never rely on color alone to distinguish letters,
grammar, or modifier meanings.

────────

6. How to construct the utilitarian script

6.1 Overall appearance

The utilitarian script is built primarily from:

• Straight horizontal, vertical, and diagonal strokes.
• Angles, corners, and notches.
• Short crossbars.
• Simple geometric shapes.
• Controlled negative space.
• Distinct silhouettes that remain readable at small sizes.

Use a common grid and a limited stroke vocabulary. Avoid making every
character a minor variation of one angular symbol; each letter must be
identifiable at a glance.

6.2 Handwriting procedure

For a typical glyph:

1. Draw the main vertical, horizontal, or diagonal stroke.
2. Add the secondary stroke that identifies the letter.
3. Add any modifier in its prescribed location.
4. Leave the standard gap before the next letter.

The final alphabet chart must specify exact stroke order and any
permitted simplified handwritten form.

6.3 Independent letters

Do not connect letters. Each glyph should remain independent so that it
can be read, edited, searched, selected, and processed digitally.

6.4 Grid and spacing

The final font specification should define:

• Standard character height and width.
• Baseline and body height.
• Allowed ascenders and descenders.
• Minimum gap between neighboring letters.
• Word-space width.
• Modifier placement zones.
• Minimum readable size.
• Monospaced and proportional font behavior.

For handwriting, use consistent proportions even if exact measurements
are not available. In digital fonts, follow the published metrics.

6.5 Technical readability

The utilitarian script must work in monochrome, low-resolution displays,
print, and plain text environments. Distinctive letter shapes must not
depend on subtle colors, gradients, shadows, or animation.

Numerals and punctuation should have their own clear designs. They must
not be confused with base letters or modifier marks.

────────

7. Shared writing direction and layout

The provisional standard for both scripts is:

• Write left to right.
• Arrange lines top to bottom.
• Use a visible space between words.
• Use a consistent line break convention.
• Keep punctuation in a consistent relationship to the text it
affects.
• Do not reverse the direction of one script to make it look more
exotic.

The same text should preserve its word order when converted between
scripts. SVO means that a basic declarative sentence normally places the
subject first, the verb second, and the object third.

The writing direction and word order are separate concepts:
left-to-right is an orthographic choice; SVO is a grammatical choice.

────────

8. Universal modifiers

Modifiers are marks added to letters or text units to express
grammatical or other standardized information. They are not additional
base letters. The 28-letter alphabet remains unchanged.

Both scripts use the same logical modifier inventory. Their appearance
and placement can differ, but their function must not.

8.1 Proposed modifier families

The meanings below are candidates for development. They are not final
until the language designer approves a complete modifier table.

────────

Family                  Visual form             Candidate function

────────

Dots                    One, two, or three dots Time, reference, or
perspective

Bars                    Short horizontal or     Aspect, completion, or
vertical strokes        duration

U-shaped marks          Rounded or squared U    Grammatical
forms                   relationships

Rings                   Closed or open circular Identity, continuity,
marks                   or recurring states

Hooks and tails         Curved or angular       Attachment, possession,
attachments             or dependency

Crossbars               Strokes crossing a      Negation, opposition, glyph                   or contrast

These are design hypotheses. Do not assume, for example, that one dot
definitively means past tense until the canonical modifier table says
so.

8.2 A modifier must have a defined scope

Every modifier must specify what it affects:

• One letter.
• A whole syllable.
• A word.
• A phrase or clause.

Do not allow scope to be inferred solely from artistic placement. If a
mark affects a word, the standard must explain how readers identify the
boundaries of that word.

The recommended baseline is to attach a modifier visually to its target
and define a fixed scope rule for each modifier type. Word- or
clause-level meanings should use an explicit marker or clearly defined
bracketing convention rather than a free-floating decorative mark.

8.3 Modifier positions

The two scripts may render modifiers differently, but every modifier
type needs a canonical logical position.

For the utilitarian script, define fixed positions such as above, below,
left, right, or in a reserved attachment zone.

For the artistic script, the mark may follow the contour of the glyph,
but it must remain within the permitted zone for that modifier and must
not appear to modify a different letter.

8.4 Stacking modifiers

A letter or text unit may eventually need more than one modifier. To
support this safely:

1. Define which modifier types may coexist.
2. Define a standard order for compatible modifiers.
3. Define the position for each modifier in a stack.
4. Explicitly prohibit combinations that conflict, unless a meaningful
combined form is specified.
5. Ensure the stack remains readable in both scripts and in small text.

Do not invent a new meaning merely by placing two marks together.
Combinations have meaning only when documented in the grammar.

8.5 One, two, and three dots

The system should distinguish one dot, two dots, and three dots
consistently. The dots must be countable and must not be mistaken for
punctuation, texture, or a decorative flourish.

If a dot family eventually represents tense or temporal reference, its
canonical table must state:

• The meaning of each count.
• Whether the meaning applies to a letter, syllable, or word.
• Whether the modifier is obligatory or optional.
• How it interacts with the verb’s ordinary tense marking.
• Whether any count is reserved or invalid.

Until that table is approved, do not assign fixed tense meanings to dot
counts in published language examples.

8.6 Modifier table requirement

Before the script can be considered fully specified, the project needs a
canonical table with at least these columns:

Field              Purpose

────────

Modifier ID        Stable machine-readable identifier
Name               Short human-readable name
Meaning            Exact grammatical or semantic function
Visual family      Dot, bar, ring, hook, and so on
Target scope       Letter, syllable, word, or clause
Artistic form      Description or glyph reference
Utilitarian form   Description or glyph reference
Position           Canonical placement rule
Stacking rules     Compatible and incompatible combinations
Transliteration    How the modifier is represented in plain text
Examples           Approved examples with explanation

This table is essential for fluency. Writers should not have to guess
what a mark means.

────────

9. Spelling and sound rules

The following is a provisional phonotactic system for building and
pronouncing words.

9.1 Syllable structure

The proposed syllable template is:

(C)(C)V(C)(C)

Where:

• C means a consonant.
• V means a vowel.
• Parentheses indicate an optional element.

Under this proposal, every syllable contains a vowel, and an onset or
coda contains at most two consonants. Not every possible cluster should
automatically be considered valid; the language needs an approved
cluster list.

Illustrative syllable shapes include:

• KA — consonant + vowel.
• KAT — consonant + vowel + consonant.
• KRA — two consonants + vowel.
• KANT — consonant + vowel + two consonants.
• KRANT — two consonants + vowel + two consonants.

These are structural illustrations, not approved vocabulary words.

9.2 Vowel sequences

The initial proposal uses five short, pure vowels and avoids phonemic
long vowels and diphthongs. Adjacent written vowels should not
automatically be pronounced as one diphthong. The final phonology must
define whether adjacent vowels belong to separate syllables and how
syllable boundaries are shown when necessary.

The sacred AEIOU sequence is a special philosophical formula and should
not be used to infer the pronunciation of every adjacent-vowel sequence
in ordinary words.

9.3 Consonant clusters

A cluster is valid only if it appears in the language’s approved
phonotactic rules or dictionary. The fact that a cluster fits the
(C)(C)V(C)(C) template does not prove that it is permitted.

The final specification should list:

• Allowed two-consonant onsets.
• Allowed two-consonant codas.
• Any forbidden combinations.
• Whether syllables may begin or end with particular consonants.
• How loanwords and names are adapted.

9.4 Stress

The provisional stress rule is penultimate stress: stress the
second-to-last syllable of a word.

Examples are not yet supplied because final syllable parsing and
exceptions have not been established. The official pronunciation guide
should explain stress with syllable-separated examples and identify any
exceptions.

9.5 Pronunciation discipline

• Pronounce each base letter consistently.
• Do not import English spelling rules.
• Do not add silent letters.
• Do not treat KH or Ñ as two base letters.
• Do not assume an artistic flourish changes pronunciation.
• If the language later permits regional accents, document which
differences are acceptable without changing word identity.

────────

10. Word boundaries, punctuation, and numerals

The following are recommended working conventions pending final
approval.

10.1 Word boundaries

Separate words with a normal space in both scripts. Do not use artistic
joining strokes to erase word boundaries. Use a line break only where
the layout allows it; a line break must not silently change the word.

If the language later adopts compounds, its orthography must state
whether each compound is written as one word, multiple words, or with a
joining mark.

10.2 Punctuation

Punctuation should be standardized across both scripts. The final system
needs clear equivalents for:

• End of sentence.
• Question.
• Exclamation or strong emphasis.
• Comma or short pause.
• Quotation.
• Parenthetical or inserted material.
• List separators.
• Colon and semicolon, if used.
• Ellipsis or deliberate trailing off.

The artistic script may style punctuation to match its calligraphic
forms, but the punctuation’s identity and function must remain clear.
The utilitarian script should use fixed, unambiguous forms.

Do not rely on line spacing, color, or decoration alone to indicate
sentence boundaries.

10.3 Numerals

The language should eventually define its own numeral glyphs and number
grammar. Until that is finalized, use a documented external numeral
convention consistently in working drafts rather than inventing native
numeral forms ad hoc.

The numeral system must specify number signs, digit values, place value
or another counting scheme, decimal notation, negative numbers,
fractions, large numbers, dates, and measurements.

10.4 Names and borrowed words

Personal names, place names, technical terms, and loanwords should
follow a published adaptation rule. The language should decide whether
names are transliterated by sound, preserved in their original spelling,
or supported by both a native form and an original form.

Do not invent special capitalization rules until the project has decided
whether case exists in either script.

────────

11. Grammar a writer must know

The scripts are writing systems, not a replacement for grammar. To write
fluently, a learner also needs a vocabulary and a complete grammar
reference.

11.1 Word order

The default order is subject–verb–object (SVO).

A schematic sentence is:

SUBJECT — VERB — OBJECT

This is a grammatical template, not a translated example. The final
language specification should provide approved words and sentences for
each common construction.

11.2 Pronouns

The planned pronoun system should cover at least first, second, and
third person, singular and plural. The current direction is to avoid
grammatical gender and use a gender-neutral third-person pronoun by
default.

The grammar should decide whether the language distinguishes inclusive
and exclusive “we”:

• Inclusive “we”: speaker plus the person or people being addressed.
• Exclusive “we”: speaker plus others, excluding the person or people
being addressed.

A complete pronoun table must define forms, plural behavior, possession,
object use, and whether pronouns may be omitted when context is clear.

11.3 Nouns and possession

The grammar should define:

• Singular and plural formation.
• Whether plural marking is obligatory.
• Definite and indefinite reference (“the” and “a/an” equivalents).
• Demonstratives (“this,” “that,” and any distance distinctions).
• Possession and association.
• Whether nouns receive case markers or rely on word order and
particles.

Do not assume English articles or plural endings map directly onto the
new language.

11.4 Verbs, tense, and aspect

The planned tense distinctions are past, present, and future. Aspect is
a separate concept from tense. The initial proposal includes perfective
and imperfective aspect, with a possible perfect aspect.

• Tense locates a situation in time.
• Aspect describes how the situation unfolds or is viewed, such as
as a whole or as ongoing.
• Perfect commonly relates an earlier situation to a later
reference point; its exact role must be defined in the language.

The grammar must specify marker forms, ordering, optionality, and
interaction. Do not use the sacred vowel formula as a substitute for
ordinary tense and aspect markers.

11.5 Negation

The provisional idea is a regular negation particle placed before the
verb. Its actual form, scope, and behavior with auxiliaries, questions,
and embedded clauses have not been finalized.

The grammar should explicitly distinguish different scopes, such as “not
everyone came” versus “no one came,” if the language intends to express
both.

11.6 Questions

The language should define a consistent way to form:

• Yes/no questions.
• Information questions such as who, what, where, when, why, and how.
• Questions embedded inside another sentence.
• Negative questions, if supported.

A question particle or a consistent syntactic construction is preferable
to relying only on intonation.

11.7 Conditionals, uncertainty, and evidence

A mature language should provide ways to distinguish hypothetical
situations, possibilities, inferences, reports, and established claims.
These may use particles or grammatical constructions.

Useful distinctions include:

• The speaker states something as known.
• The speaker infers it from evidence.
• The speaker reports what someone else said.
• The speaker considers it possible but unconfirmed.
• The speaker does not know.

The exact forms are not yet specified. Until they are, do not improvise
them as though they were official grammar.

11.8 Word formation

The language should establish consistent ways to create compounds and
derive related nouns, verbs, adjectives, and adverbs. It should also
specify how technical vocabulary and loanwords are formed.

A fluent writer should be able to create a new word predictably, check
whether it follows phonotactics, and record its meaning without
inventing a new rule for each case.

────────

12. Artistic expression without changing the language

The artistic script may add expressive depth, but the distinction
between literal meaning and presentation should remain clear.

Consider the English illustrative sentence:

> The river remembers.

In a literary context, this may evoke history, continuity, or traces of
past events. In a technical context, the writer would need to specify
whether the sentence describes a literal information-storage process or
uses a metaphor.

The same principle applies to the constructed language:

• Literal meaning: what the words and grammar assert.
• Contextual meaning: what the situation helps the reader infer.
• Expressive meaning: what the writer evokes through metaphor,
rhythm, composition, or emphasis.

Artistic spacing, calligraphy, and color can guide interpretation, but
they must not secretly change the lexical meaning of a word. If a visual
feature changes grammatical meaning, it is a modifier and must be
documented as such.

The utilitarian script should make structure easier to inspect. It
should not prevent metaphor, humor, or literature.

────────

13. Digital writing and conversion

A usable modern script needs a technical standard in addition to a
handwritten alphabet.

13.1 Canonical text representation

The project should define an internal representation that stores:

• Base-letter identity.
• Word and sentence boundaries.
• Modifier identity.
• Modifier target and scope.
• Punctuation.
• Any meaningful non-letter notation.

Do not use a screenshot or an artistic font as the sole storage format.
The same underlying text must be available as structured data so the two
scripts can be rendered from it.

13.2 Transliteration

A transliteration system should allow users to type the language before
native glyph fonts and keyboards are widely available.

The current letter labels in Section 4 are provisional. The final
standard must define how to enter each letter and modifier, including
KH, Ñ, and stacked modifiers, without ambiguity.

The transliteration must be reversible: a valid native-script text
should convert to transliteration and back without losing letter or
modifier identity.

13.3 Fonts and rendering

The project should eventually provide:

• An artistic-script font.
• A utilitarian-script font.
• A fallback transliteration font or plain-text representation.
• Rules for combining and positioning modifiers.
• A method to avoid collisions between adjacent marks.
• Font tests at small sizes and in monochrome.
• A versioning policy for changes to glyph shapes.

The logical identity of a letter must not depend on which font renders
it.

13.4 Unicode and normalization

Do not assume that every mark should be represented as an ordinary
Unicode combining character. Some combinations may render inconsistently
across software. The project should decide whether to use existing
Unicode characters, a dedicated encoding proposal in the future, or a
structured text format with custom rendering.

Normalization rules must define when two text sequences count as the
same text. Search, copy-and-paste, and conversion must work
consistently.

13.5 Accessibility and search

Digital tools should support:

• Text selection and copy-and-paste.
• Search by word and by transliteration.
• Screen-reader output using a documented pronunciation or
transliteration.
• Keyboard input without requiring memorization of dozens of obscure
shortcuts.
• Reliable line wrapping and cursor movement.
• Clear visual distinction between letters, modifiers, punctuation,
and numerals.

────────

14. How to learn to write fluently

Follow this sequence rather than trying to memorize everything at once.

Stage 1: Learn the sounds

• Learn the five vowels.
• Learn the 23 consonants.
• Practice distinguishing similar sounds, especially K/Q, S/X, C/J,
and R/L.
• Learn the official syllable and stress rules when finalized.

Stage 2: Learn the 28 glyphs

• Study the canonical alphabet chart.
• Learn each letter’s name, sound, and stroke order.
• Practice identifying glyphs in isolation and inside words.
• Practice both printed and handwritten forms.

Stage 3: Learn the writing rhythm

• Write short syllables.
• Write approved words.
• Practice consistent word spacing and line layout.
• Learn punctuation and numerals when their standards are published.

Stage 4: Learn modifiers

• Memorize the canonical modifier table.
• Practice identifying each mark and its scope.
• Practice compatible modifier stacks.
• Convert modified words between the two scripts and verify that
nothing changes.

Stage 5: Learn grammar

• Practice SVO sentences.
• Learn pronouns, nouns, possession, and plural formation.
• Learn tense, aspect, negation, and questions.
• Learn how to mark uncertainty and handle ambiguity once those rules
are approved.

Stage 6: Practice both styles

• Copy the same short text in both scripts.
• Write an everyday note in each.
• Write a short literary passage in the artistic script.
• Write a technical instruction in the utilitarian script.
• Convert each passage and verify that the underlying text remains the
same.

Stage 7: Read without transliteration

Once the glyphs and grammar are familiar, practice reading native script
directly rather than mentally converting each letter to Latin
characters.

Fluency means recognizing words and grammatical structures directly, not
merely drawing the shapes accurately.

────────

15. Quality checklist for writers

Before sharing a text, check the following:

☐ Every base glyph represents one of the 28 approved letters.
☐ The spelling follows the current dictionary and phonotactic
rules.
☐ The text follows the standard writing direction.
☐ Word boundaries are visible and unambiguous.
☐ Modifiers have documented meanings and correct scope.
☐ Modifier stacks follow the approved order.
☐ The artistic script’s flourishes do not obscure letters or
change grammar.
☐ The utilitarian script uses standard glyph forms and spacing.
☐ Punctuation and numerals follow the published convention.
☐ The grammar matches the intended meaning.
☐ Conversion to the other script preserves the underlying text.
☐ Any provisional or invented form is clearly marked as such.

────────

16. What must be completed before this becomes a final fluency manual

This manual establishes a usable design framework, but a new writer
cannot truly write fluently until the following reference materials
exist.

1. Canonical alphabet chart: all 28 native glyphs in both scripts,
with letter names, pronunciations, stroke order, handwritten forms,
and digital identifiers.
2. Approved phonology: final IPA values, permitted consonant
clusters, syllable boundaries, stress rules, and pronunciation
exceptions.
3. Canonical modifier table: final meanings, scope, placement,
stacking rules, and transliteration for every mark.
4. Complete grammar: pronouns, noun forms, articles, possession,
verb morphology, tense, aspect, negation, questions, conditionals,
and uncertainty.
5. Dictionary: approved words with pronunciations, definitions,
grammatical categories, and example sentences.
6. Punctuation and numeral standard: all sentence marks, quotation
conventions, numerals, dates, and measurements.
7. Transliteration standard: unambiguous keyboard input and
reversible conversion.
8. Digital encoding and fonts: canonical text representation,
rendering rules, and accessible input.
9. Approved parallel texts: sample passages written in both scripts
and checked for lossless conversion.
10. Version policy: a way to distinguish established rules from
proposals and record future changes.

Until these items are completed, this document should be described as a
working writing-system manual, not a fully finalized language
specification.

────────

17. Core principle

One language. Two scripts. Shared grammar. Shared modifier meanings.
Different visual priorities.

The artistic script gives the language room for elegance, rhythm,
metaphor, and deliberate visual composition. The utilitarian script
gives it consistency, compactness, and operational clarity. Both must
remain readable, learnable, and convertible.

A fluent writer should be able to express the same thought in either
script, understand the same grammatical information, and move between
expressive and precise writing without changing the language itself.