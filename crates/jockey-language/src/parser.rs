//! JOCKY Parser — Pest-based parser for JOCKY DSL

use pest::Parser;
use pest_derive::Parser;
use crate::ast::*;
use crate::span::{Span, Position, Spanned, HasSpan};

#[derive(Parser)]
#[grammar = "parser.pest"]
pub struct JockeyParser;

/// Parse error with source location
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Parse error at {span}: {message}")]
    ParseError { message: String, span: Span },
    
    #[error("Pest parse error: {0}")]
    PestError(#[from] pest::error::Error<Rule>),
}

impl ParseError {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Self::ParseError { message: message.into(), span }
    }
}

/// Parse JOCKY source into AST
pub fn parse(source: &str) -> Result<AstModule, ParseError> {
    let pairs = JockeyParser::parse(Rule::investigation, source)
        .map_err(ParseError::PestError)?;
    
    let mut pairs = pairs.peekable();
    let investigation_pair = pairs.next().unwrap();
    
    let mut name = String::new();
    let mut statements = Vec::new();
    let mut span = Span::single(Position::start());
    
    for inner in investigation_pair.into_inner() {
        match inner.as_rule() {
            Rule::identifier => {
                name = inner.as_str().to_string();
                span = pest_span_to_span(inner.as_span());
            }
            Rule::string => {
                name = unescape_string(inner.as_str());
                span = pest_span_to_span(inner.as_span());
            }
            Rule::statement => {
                statements.push(parse_statement(inner)?);
            }
            _ => {}
        }
    }
    
    Ok(AstModule { name, statements, span })
}

fn parse_statement(pair: pest::iterators::Pair<Rule>) -> Result<Statement, ParseError> {
    let span = pest_span_to_span(pair.as_span());
    let inner = pair.into_inner().next().unwrap();
    
    match inner.as_rule() {
        Rule::hypothesis => parse_hypothesis(inner, span),
        Rule::collect => parse_collect(inner, span),
        Rule::filter => parse_filter(inner, span),
        Rule::r#match => parse_match(inner, span),
        Rule::correlate => parse_correlate(inner, span),
        Rule::timeline => parse_timeline(inner, span),
        Rule::bind => parse_bind(inner, span),
        Rule::export => parse_export(inner, span),
        Rule::verify => parse_verify(inner, span),
        _ => Err(ParseError::new(format!("Unknown statement type: {:?}", inner.as_rule()), span)),
    }
}

fn parse_hypothesis(pair: pest::iterators::Pair<Rule>, span: Span) -> Result<Statement, ParseError> {
    let mut description = String::new();
    let mut mitre_tags = Vec::new();
    
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::string => {
                description = unescape_string(inner.as_str());
            }
            Rule::mitre_list => {
                for tag in inner.into_inner() {
                    mitre_tags.push(unescape_string(tag.as_str()));
                }
            }
            _ => {}
        }
    }
    
    Ok(Statement::Hypothesis(HypothesisDecl {
        description,
        mitre_tags,
        span,
    }))
}

fn parse_collect(pair: pest::iterators::Pair<Rule>, span: Span) -> Result<Statement, ParseError> {
    let mut evidence_type = EvidenceType::Process;
    let mut binding = String::new();
    let mut filter = None;
    
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::evidence_type => {
                evidence_type = match inner.as_str() {
                    "process" => EvidenceType::Process,
                    "file" => EvidenceType::File,
                    "registry" => EvidenceType::Registry,
                    "config" => EvidenceType::Config,
                    "logs" => EvidenceType::Logs,
                    "network" => EvidenceType::Network,
                    _ => return Err(ParseError::new(format!("Unknown evidence type: {}", inner.as_str()), pest_span_to_span(inner.as_span()))),
                };
            }
            Rule::identifier => {
                binding = inner.as_str().to_string();
            }
            Rule::where_clause => {
                for expr in inner.into_inner() {
                    filter = Some(parse_expression(expr)?);
                }
            }
            _ => {}
        }
    }
    
    Ok(Statement::Collect(CollectDecl {
        evidence_type,
        binding,
        filter,
        span,
    }))
}

fn parse_filter(pair: pest::iterators::Pair<Rule>, span: Span) -> Result<Statement, ParseError> {
    let mut source = String::new();
    let mut filter = None;
    
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::identifier => source = inner.as_str().to_string(),
            Rule::where_clause => {
                for expr in inner.into_inner() {
                    filter = Some(parse_expression(expr)?);
                }
            }
            _ => {}
        }
    }
    
    Ok(Statement::Filter(FilterDecl {
        source,
        filter: filter.unwrap_or_else(|| Expression::Literal(Literal::Boolean(true))),
        span,
    }))
}

fn parse_match(pair: pest::iterators::Pair<Rule>, span: Span) -> Result<Statement, ParseError> {
    let mut source = String::new();
    let mut pattern = None;
    
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::identifier => source = inner.as_str().to_string(),
            Rule::where_clause => {
                for expr in inner.into_inner() {
                    pattern = Some(parse_expression(expr)?);
                }
            }
            _ => {}
        }
    }
    
    Ok(Statement::Match(MatchDecl {
        source,
        pattern: pattern.unwrap_or_else(|| Expression::Literal(Literal::Boolean(true))),
        span,
    }))
}

fn parse_correlate(pair: pest::iterators::Pair<Rule>, span: Span) -> Result<Statement, ParseError> {
    let mut source = String::new();
    let mut target = String::new();
    let mut relation = String::new();
    let mut binding = String::new();
    let mut params = CorrelationParams { window: None };
    
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::identifier => {
                if source.is_empty() {
                    source = inner.as_str().to_string();
                } else if target.is_empty() {
                    target = inner.as_str().to_string();
                } else if binding.is_empty() {
                    binding = inner.as_str().to_string();
                }
            }
            Rule::string => {
                relation = unescape_string(inner.as_str());
            }
            Rule::correlate_params => {
                for param in inner.into_inner() {
                    match param.as_rule() {
                        Rule::window => {
                            let mut value = 0;
                            let mut unit = TimeUnit::Seconds;
                            for p in param.into_inner() {
                                match p.as_rule() {
                                    Rule::integer => {
                                        value = p.as_str().parse().unwrap_or(0);
                                    }
                                    Rule::time_unit => {
                                        unit = match p.as_str() {
                                            "s" => TimeUnit::Seconds,
                                            "m" => TimeUnit::Minutes,
                                            "h" => TimeUnit::Hours,
                                            _ => TimeUnit::Seconds,
                                        };
                                    }
                                    _ => {}
                                }
                            }
                            params.window = Some(Duration { value, unit });
                        }
                        _ => {}
                    }
                }
            },
            _ => {}
        }
    }
    
    Ok(Statement::Correlate(CorrelateDecl {
        source,
        target,
        relation,
        binding,
        params,
        span,
    }))
}

fn parse_timeline(pair: pest::iterators::Pair<Rule>, span: Span) -> Result<Statement, ParseError> {
    let mut name = String::new();
    let mut sources = Vec::new();
    
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::identifier => {
                if name.is_empty() {
                    name = inner.as_str().to_string();
                } else {
                    sources.push(inner.as_str().to_string());
                }
            }
            Rule::string => {
                name = unescape_string(inner.as_str());
            }
            _ => {}
        }
    }
    
    Ok(Statement::Timeline(TimelineDecl {
        name,
        sources,
        span,
    }))
}

fn parse_bind(pair: pest::iterators::Pair<Rule>, span: Span) -> Result<Statement, ParseError> {
    let mut hypothesis = String::new();
    let mut evidence_bindings = Vec::new();
    
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::string => hypothesis = unescape_string(inner.as_str()),
            Rule::identifier => evidence_bindings.push(inner.as_str().to_string()),
            _ => {}
        }
    }
    
    Ok(Statement::Bind(BindDecl {
        hypothesis,
        evidence_bindings,
        span,
    }))
}

fn parse_export(pair: pest::iterators::Pair<Rule>, span: Span) -> Result<Statement, ParseError> {
    let mut output_type = OutputType::Case;
    let mut name = String::new();
    let mut format = ExportFormat::Markdown;
    
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::output_type => {
                output_type = match inner.as_str() {
                    "case" => OutputType::Case,
                    "graph" => OutputType::Graph,
                    "timeline" => OutputType::Timeline,
                    "report" => OutputType::Report,
                    _ => OutputType::Case,
                };
            }
            Rule::identifier => name = inner.as_str().to_string(),
            Rule::string => name = unescape_string(inner.as_str()),
            Rule::format_spec => {
                format = match inner.as_str() {
                    "case_uco" => ExportFormat::CaseUco,
                    "cytoscape" => ExportFormat::Cytoscape,
                    "timesketch" => ExportFormat::Timesketch,
                    "markdown" => ExportFormat::Markdown,
                    "graphml" => ExportFormat::Graphml,
                    "dot" => ExportFormat::Dot,
                    _ => ExportFormat::Markdown,
                };
            }
            _ => {}
        }
    }
    
    Ok(Statement::Export(ExportDecl {
        output_type,
        name,
        format,
        span,
    }))
}

fn parse_verify(pair: pest::iterators::Pair<Rule>, span: Span) -> Result<Statement, ParseError> {
    let mut target = String::new();
    
    for inner in pair.into_inner() {
        if let Rule::identifier = inner.as_rule() {
            target = inner.as_str().to_string();
        }
    }
    
    Ok(Statement::Verify(VerifyDecl { target, span }))
}

fn parse_expression(pair: pest::iterators::Pair<Rule>) -> Result<Expression, ParseError> {
    // Parse comparison first, then handle and/or
    let mut comparisons = Vec::new();
    let mut operators = Vec::new();
    
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::comparison => comparisons.push(parse_comparison(inner)?),
            Rule::and => operators.push(BinaryOp::And),
            Rule::or => operators.push(BinaryOp::Or),
            _ => {}
        }
    }
    
    if comparisons.is_empty() {
        return Err(ParseError::new("Empty expression".to_string(), Span::single(Position::start())));
    }
    
    if comparisons.len() == 1 && operators.is_empty() {
        return Ok(comparisons.remove(0));
    }
    
    // Build binary expression tree
    let mut expr = comparisons.remove(0);
    for (op, right) in operators.into_iter().zip(comparisons) {
        expr = Expression::Binary(BinaryExpr {
            left: Box::new(expr),
            operator: op,
            right: Box::new(right),
            span: Span::single(Position::start()), // TODO: proper span
        });
    }
    
    Ok(expr)
}

fn parse_comparison(pair: pest::iterators::Pair<Rule>) -> Result<Expression, ParseError> {
    let mut left = String::new();
    let mut op = BinaryOp::Eq;
    let mut right: Option<Expression> = None;
    
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::identifier => {
                if left.is_empty() {
                    left = inner.as_str().to_string();
                } else {
                    // This shouldn't happen in comparison
                }
            }
            Rule::operator => {
                op = match inner.as_str() {
                    "==" => BinaryOp::Eq,
                    "!=" => BinaryOp::Neq,
                    ">" => BinaryOp::Gt,
                    "<" => BinaryOp::Lt,
                    ">=" => BinaryOp::Gte,
                    "<=" => BinaryOp::Lte,
                    "contains" => BinaryOp::Contains,
                    "matches" => BinaryOp::Matches,
                    "in" => BinaryOp::In,
                    _ => BinaryOp::Eq,
                };
            }
            Rule::value => {
                right = Some(Expression::Literal(parse_value(inner)?));
            }
            Rule::array => {
                let mut arr = Vec::new();
                for val in inner.into_inner() {
                    arr.push(parse_value(val)?);
                }
                right = Some(Expression::Literal(Literal::Array(arr)));
            }
            _ => {}
        }
    }
    
    let right_expr = right.unwrap_or(Expression::Literal(Literal::Boolean(true)));
    
    Ok(Expression::Binary(BinaryExpr {
        left: Box::new(Expression::Identifier(left)),
        operator: op,
        right: Box::new(right_expr),
        span: Span::single(Position::start()),
    }))
}

fn parse_value(pair: pest::iterators::Pair<Rule>) -> Result<Literal, ParseError> {
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::string => return Ok(Literal::String(unescape_string(inner.as_str()))),
            Rule::integer => return Ok(Literal::Integer(inner.as_str().parse().unwrap_or(0))),
            Rule::float => return Ok(Literal::Float(inner.as_str().parse().unwrap_or(0.0))),
            Rule::boolean => return Ok(Literal::Boolean(inner.as_str().parse().unwrap_or(false))),
            Rule::array => {
                let mut arr = Vec::new();
                for val in inner.into_inner() {
                    arr.push(parse_value(val)?);
                }
                return Ok(Literal::Array(arr));
            }
            _ => {}
        }
    }
    Ok(Literal::Boolean(false))
}

fn unescape_string(s: &str) -> String {
    // Remove surrounding quotes
    let s = if s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len()-1]
    } else {
        s
    };
    
    // Handle escape sequences
    s.replace("\\\"", "\"")
     .replace("\\\\", "\\")
     .replace("\\n", "\n")
     .replace("\\t", "\t")
     .replace("\\r", "\r")
}

/// Convert pest span to our Span type
fn pest_span_to_span(pest_span: pest::Span) -> Span {
    let (start_line, start_col) = pest_span.start_pos().line_col();
    let (end_line, end_col) = pest_span.end_pos().line_col();
    let start_offset = pest_span.start();
    let end_offset = pest_span.end();
    
    Span::new(
        Position::new(start_line, start_col, start_offset),
        Position::new(end_line, end_col, end_offset),
    )
}