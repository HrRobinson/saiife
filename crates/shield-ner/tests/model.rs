//! The tract runtime on a synthetic ONNX graph built in code (no model file,
//! no download): `logits = Gather(E, input_ids)`, where the rows of `E` are
//! chosen per vocab id so the graph acts as a tiny token classifier.

use prost::Message;
use saiife_shield_ner::model::NerModel;
use saiife_shield_ner::NerError;
use tract_onnx::pb;

const VOCAB: &[&str] = &[
    "[PAD]", "[UNK]", "[CLS]", "[SEP]", "hvad", "skylder", "sø", "##ren", "i", "aarhus", "?",
];
const LABELS: &[&str] = &["O", "B-PER", "I-PER", "B-LOC", "I-LOC"];

fn vocab() -> Vec<u8> {
    VOCAB.join("\n").into_bytes()
}

/// The label each vocab id is tagged with.
fn tag_of(tok: &str) -> usize {
    match tok {
        "sø" => 1,
        "##ren" => 2,
        "aarhus" => 3,
        _ => 0,
    }
}

fn labels_json(n_labels: usize, inputs: &[&str]) -> Vec<u8> {
    let id2label: serde_json::Map<String, serde_json::Value> = LABELS
        .iter()
        .take(n_labels)
        .enumerate()
        .map(|(i, l)| (i.to_string(), serde_json::Value::from(*l)))
        .collect();
    serde_json::json!({
        "id2label": id2label,
        "do_lower_case": true,
        "max_len": 512,
        "inputs": inputs,
        "strip_accents": false,
    })
    .to_string()
    .into_bytes()
}

fn i64_input(name: &str) -> pb::ValueInfoProto {
    use pb::tensor_shape_proto::{dimension::Value, Dimension};
    let dim = |v: Value| Dimension {
        value: Some(v),
        ..Default::default()
    };
    pb::ValueInfoProto {
        name: name.to_string(),
        r#type: Some(pb::TypeProto {
            value: Some(pb::type_proto::Value::TensorType(pb::type_proto::Tensor {
                elem_type: pb::tensor_proto::DataType::Int64 as i32,
                shape: Some(pb::TensorShapeProto {
                    dim: vec![dim(Value::DimValue(1)), dim(Value::DimParam("S".into()))],
                }),
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// `inputs`: the graph inputs (only `input_ids` is used).
fn model_bytes(inputs: &[&str]) -> Vec<u8> {
    let l = LABELS.len();
    let mut e = vec![0f32; VOCAB.len() * l];
    for (v, tok) in VOCAB.iter().enumerate() {
        e[v * l + tag_of(tok)] = 10.0;
    }
    let table = pb::TensorProto {
        name: "E".into(),
        dims: vec![VOCAB.len() as i64, l as i64],
        data_type: pb::tensor_proto::DataType::Float as i32,
        float_data: e,
        ..Default::default()
    };
    let gather = pb::NodeProto {
        name: "classify".into(),
        op_type: "Gather".into(),
        input: vec!["E".into(), "input_ids".into()],
        output: vec!["logits".into()],
        ..Default::default()
    };
    let graph = pb::GraphProto {
        name: "p46-synthetic".into(),
        node: vec![gather],
        initializer: vec![table],
        input: inputs.iter().map(|n| i64_input(n)).collect(),
        output: vec![pb::ValueInfoProto {
            name: "logits".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    pb::ModelProto {
        ir_version: 7,
        opset_import: vec![pb::OperatorSetIdProto {
            domain: String::new(),
            version: 13,
        }],
        graph: Some(graph),
        ..Default::default()
    }
    .encode_to_vec()
}

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
