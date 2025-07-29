use std::fmt::Write;

use proc_macro::TokenStream;

// multiversion crate doesn't work with trait methods and can't bring your own feature detection
// so here is a contraption there will generate a suffixed variant of the function for each feature

#[proc_macro_attribute]
pub fn generate_target_variant(attrs: TokenStream, input: TokenStream) -> TokenStream {
    let attrs = attrs.to_string();

    let feature = attrs
        .trim()
        .strip_prefix("\"")
        .unwrap()
        .strip_suffix("\"")
        .unwrap()
        .split(",")
        .collect::<Vec<_>>();

    let mut comments = Vec::new();

    let input_str = input.to_string();
    let mut input_str = input_str.lines();

    let mut def_line = input_str.next().unwrap();

    while def_line.trim().starts_with("//")
        || def_line
            .trim()
            .strip_prefix("#")
            .map_or(false, |s| s.trim().starts_with("["))
    {
        comments.push(def_line.trim().to_string());
        let Some(def_line_next) = input_str.next() else {
            return "".parse().unwrap();
        };
        def_line = def_line_next;
    }

    let rest = if def_line.trim().starts_with("pub") {
        let trimmed = def_line.trim();
        let split = trimmed
            .char_indices()
            .filter(|(_, c)| c.is_whitespace())
            .next()
            .unwrap()
            .0;
        &trimmed[split..]
    } else {
        def_line
    };

    let Some(rest) = rest.trim().strip_prefix("fn ") else {
        panic!("Expected a function definition, got {}", rest);
    };

    let name = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>();

    let def_line_mutated =
        def_line.replace(&name, format!("{}_{}", name, feature.join("_")).as_str());

    let rest_lines = input_str.collect::<Vec<_>>();

    let mut output = String::new();
    for comment in comments.iter() {
        writeln!(&mut output, "{}", comment).unwrap();
    }
    writeln!(&mut output, "{}", def_line).unwrap();
    for line in rest_lines.iter() {
        writeln!(&mut output, "{}", line).unwrap();
    }

    for comment in comments.iter() {
        writeln!(&mut output, "{}", comment).unwrap();
    }
    writeln!(
        &mut output,
        "// This is a generated function for CPU target {}",
        feature.join(", ")
    )
    .unwrap();
    for feature in feature.iter() {
        writeln!(&mut output, "#[target_feature(enable = \"{}\")]", feature).unwrap();
    }
    writeln!(&mut output, "{}", def_line_mutated).unwrap();
    output.extend(rest_lines);

    output.parse().unwrap()
}
