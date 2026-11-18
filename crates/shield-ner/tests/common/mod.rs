//! The synthetic ONNX graph shared by the model and helper tests: built in
//! code (no model file, no download): `logits = Gather(E, input_ids)`, where
//! the rows of `E` are chosen per vocab id so the graph acts as a tiny token
//! classifier.
#![allow(dead_code)]

use prost::Message;
use tract_onnx::pb;

pub const VOCAB: &[&str] = &[
    "[PAD]", "[UNK]", "[CLS]", "[SEP]", "hvad", "skylder", "sø", "##ren", "i", "aarhus", "?",
];
pub const LABELS: &[&str] = &["O", "B-PER", "I-PER", "B-LOC", "I-LOC"];

pub fn vocab() -> Vec<u8> {
    VOCAB.join("\n").into_bytes()
}

/// The label each vocab id is tagged with.
pub fn tag_of(tok: &str) -> usize {
    match tok {
        "sø" => 1,
        "##ren" => 2,
        "aarhus" => 3,
        _ => 0,
    }
}

pub fn labels_json(n_labels: usize, inputs: &[&str]) -> Vec<u8> {
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

pub fn i64_input(name: &str) -> pb::ValueInfoProto {
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
pub fn model_bytes(inputs: &[&str]) -> Vec<u8> {
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
