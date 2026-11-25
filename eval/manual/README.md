# Manual page set

51 live pages captured with `eval/capture.py`. Each snapshot is the element list the extension's
`content.js` extracts, so it is exactly the detector's input. The set mixes retail, travel,
subscription, news and control pages.

**Status: proposed, not verified.** Claude drafted the `proposed_labels` from a condensed view of
each snapshot (`python eval/review.py`). A human must confirm them before they count:
`evaluate.py` only scores rows with `"verified": true`, using `labels` (not `proposed_labels`).

## How to review a page

1. `python eval/review.py <id>` shows the relevant elements. Open `snapshots/<id>.json` for everything.
2. Read `proposed_labels` and `proposal_note` in `pages.jsonl`.
3. Set `labels` to the pattern types you agree are present **in the captured snapshot**, then set
   `"verified": true`. Add anything you disagree about to `notes`.
4. `python eval/review.py --status` shows progress. `python eval/evaluate.py --mode all` re-scores.

Label at the page level: a type is present if at least one element on the page shows it.

## Labeling guide

Follow Mathur et al.'s definitions: label the *claim*. We can't check whether a deadline or stock
count is true.

| Type | Label when the page shows… | Not this |
|---|---|---|
| `fake_urgency` | A deadline or time pressure: "ends Dec 4", "today only", "limited-time offer", a countdown | A plain "Sale" or "% off" badge |
| `fake_scarcity` | Low-stock or high-demand claims: "only 2 left", "in demand", "9% claimed" | "In stock"; "100+ bought" (social proof, out of scope) |
| `preselected_option` | A pre-checked box or default that adds something extra (insurance, newsletter, add-on) | Product variant pickers; billing-period toggles |
| `hidden_fees` | Fees added beyond the advertised price, or prices that exclude fees | Shipping clearly listed with the price |
| `confirmshaming` | A decline option worded to guilt you | A neutral "No thanks" |
| `forced_consent` | Consent with no equal way to refuse: accept-only banners, "by using this site you agree", reject hidden as a small link | Equal Accept / Reject buttons |
| `disguised_ad` | Ads styled as site controls or editorial content | Clearly labeled "Sponsored" / "Advertisement" |

## Known gaps

- Mostly homepages and pricing pages. There are few checkouts, so `preselected_option`,
  `hidden_fees`, `confirmshaming` and `disguised_ad` have little or no support here.
- Captured from India. Several EU consent prompts (Guardian, Spiegel, Independent) did not appear.
- 25 candidate sites served bot walls to the headless browser and were removed, not worked
  around. This biases the set toward sites that tolerate automation.
- Live pages change; re-capturing will produce different snapshots and may need new labels.
