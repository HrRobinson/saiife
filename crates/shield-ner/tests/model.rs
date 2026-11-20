//! The tract runtime on a synthetic ONNX graph built in code (no model file,
//! no download): `logits = Gather(E, input_ids)`, where the rows of `E` are
//! chosen per vocab id so the graph acts as a tiny token classifier.

mod common;

use common::{labels_json, model_bytes, vocab};
use saiife_shield_ner::model::NerModel;
use saiife_shield_ner::NerError;

const TEXT: &str = "Hvad skylder Søren i Aarhus?";

fn spans(m: &NerModel, text: &str) -> Vec<(String, String)> {
    m.detect(text)
        .unwrap()
        .into_iter()
        .map(|s| (s.label.clone(), text[s.start..s.end].to_string()))
        .collect()
}

#[test]
fn synthetic_graph_tags_tokens() {
    let inputs = ["input_ids", "attention_mask"];
    let m = NerModel::load(&model_bytes(&inputs), &vocab(), &labels_json(5, &inputs)).unwrap();
    assert_eq!(
        spans(&m, TEXT),
        vec![
            ("PER".to_string(), "Søren".to_string()),
            ("LOC".to_string(), "Aarhus".to_string())
        ]
    );
    let s = m.detect(TEXT).unwrap();
    assert!(s.iter().all(|s| s.score > 0.99 && s.score <= 1.0));
    let mut l = m.labels();
    l.sort();
    assert_eq!(l, vec!["LOC", "PER"]);
    assert!(m.detect("").unwrap().is_empty());
    // long text: many windows (max_len 512), every name found exactly once
    let long = TEXT.repeat(200);
    let found = spans(&m, &long);
    assert_eq!(found.len(), 400);
    // over MAX_TEXT bytes refuses with a fixed text
    let huge = "a ".repeat(saiife_shield::ner_proto::MAX_TEXT);
    assert!(matches!(
        m.detect(&huge),
        Err(NerError::Model("text too long"))
    ));
}

#[test]
fn token_type_ids_input() {
    let inputs = ["input_ids", "attention_mask", "token_type_ids"];
    let m = NerModel::load(&model_bytes(&inputs), &vocab(), &labels_json(5, &inputs)).unwrap();
    assert_eq!(spans(&m, TEXT).len(), 2);
    // the labels file must name the model's inputs
    let two = ["input_ids", "attention_mask"];
    assert!(matches!(
        NerModel::load(&model_bytes(&inputs), &vocab(), &labels_json(5, &two)),
        Err(NerError::Model("model inputs do not match the labels file"))
    ));
}

#[test]
fn broken_model_refuses() {
    let inputs = ["input_ids", "attention_mask"];
    let bytes = model_bytes(&inputs);
    for cut in [0, 1, 7, bytes.len() / 2, bytes.len() - 1] {
        let r = NerModel::load(&bytes[..cut], &vocab(), &labels_json(5, &inputs));
        assert!(matches!(r, Err(NerError::Model(_))), "cut at {cut}");
    }
    let r = NerModel::load(b"\xff\xfe not onnx", &vocab(), &labels_json(5, &inputs));
    assert!(matches!(r, Err(NerError::Model(_))));
}

#[test]
fn labels_mismatch_refuses() {
    let inputs = ["input_ids", "attention_mask"];
    let r = NerModel::load(&model_bytes(&inputs), &vocab(), &labels_json(3, &inputs))
        .and_then(|m| m.detect(TEXT));
    assert!(matches!(
        r,
        Err(NerError::Model("labels do not match the model output"))
    ));
}

#[test]
fn labels_without_per_refuse() {
    let inputs = ["input_ids", "attention_mask"];
    // one label only: "O", so no PER
    let r = NerModel::load(&model_bytes(&inputs), &vocab(), &labels_json(1, &inputs));
    assert!(matches!(
        r,
        Err(NerError::Model("labels file has no PER label"))
    ));
}
