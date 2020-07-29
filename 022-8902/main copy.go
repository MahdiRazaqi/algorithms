// package main

// import (
// 	"reflect"
// 	"strconv"
// 	"time"
// )

// func Unmarshal(in []byte, out interface{}) (err error) {
// 	return unmarshal(in, out, false)
// }

// func unmarshal(in []byte, out interface{}, strict bool) (err error) {
// 	defer handleErr(&err)
// 	d := newDecoder(strict)
// 	p := newParser(in)
// 	defer p.destroy()
// 	node := p.parse()
// 	if node != nil {
// 		v := reflect.ValueOf(out)
// 		if v.Kind() == reflect.Ptr && !v.IsNil() {
// 			v = v.Elem()
// 		}
// 		d.unmarshal(node, v)
// 	}
// 	if len(d.terrors) > 0 {
// 		return &TypeError{d.terrors}
// 	}
// 	return nil
// }

// func handleErr(err *error) {
// 	if v := recover(); v != nil {
// 		if e, ok := v.(yamlError); ok {
// 			*err = e.err
// 		} else {
// 			panic(v)
// 		}
// 	}
// }

// var (
// 	mapItemType    = reflect.TypeOf(MapItem{})
// 	durationType   = reflect.TypeOf(time.Duration(0))
// 	defaultMapType = reflect.TypeOf(map[interface{}]interface{}{})
// 	ifaceType      = defaultMapType.Elem()
// 	timeType       = reflect.TypeOf(time.Time{})
// 	ptrTimeType    = reflect.TypeOf(&time.Time{})
// )

// func newDecoder(strict bool) *decoder {
// 	d := &decoder{mapType: defaultMapType, strict: strict}
// 	d.aliases = make(map[*node]bool)
// 	return d
// }


// type parser struct {
// 	parser   yaml_parser_t
// 	event    yaml_event_t
// 	doc      *node
// 	doneInit bool
// }

// func newParser(b []byte) *parser {
// 	p := parser{}
// 	if !yaml_parser_initialize(&p.parser) {
// 		panic("failed to initialize YAML emitter")
// 	}
// 	if len(b) == 0 {
// 		b = []byte{'\n'}
// 	}
// 	yaml_parser_set_input_string(&p.parser, b)
// 	return &p
// }

// func (p *parser) destroy() {
// 	if p.event.typ != yaml_NO_EVENT {
// 		yaml_event_delete(&p.event)
// 	}
// 	yaml_parser_delete(&p.parser)
// }

// func (p *parser) parse() *node {
// 	p.init()
// 	switch p.peek() {
// 	case yaml_SCALAR_EVENT:
// 		return p.scalar()
// 	case yaml_ALIAS_EVENT:
// 		return p.alias()
// 	case yaml_MAPPING_START_EVENT:
// 		return p.mapping()
// 	case yaml_SEQUENCE_START_EVENT:
// 		return p.sequence()
// 	case yaml_DOCUMENT_START_EVENT:
// 		return p.document()
// 	case yaml_STREAM_END_EVENT:
// 		// Happens when attempting to decode an empty buffer.
// 		return nil
// 	default:
// 		panic("attempted to parse unknown event: " + p.event.typ.String())
// 	}
// }
// func (p *parser) alias() *node {
// 	n := p.node(aliasNode)
// 	n.value = string(p.event.anchor)
// 	n.alias = p.doc.anchors[n.value]
// 	if n.alias == nil {
// 		failf("unknown anchor '%s' referenced", n.value)
// 	}
// 	p.expect(yaml_ALIAS_EVENT)
// 	return n
// }

// func (p *parser) mapping() *node {
// 	n := p.node(mappingNode)
// 	p.anchor(n, p.event.anchor)
// 	p.expect(yaml_MAPPING_START_EVENT)
// 	for p.peek() != yaml_MAPPING_END_EVENT {
// 		n.children = append(n.children, p.parse(), p.parse())
// 	}
// 	p.expect(yaml_MAPPING_END_EVENT)
// 	return n
// }
// func (p *parser) sequence() *node {
// 	n := p.node(sequenceNode)
// 	p.anchor(n, p.event.anchor)
// 	p.expect(yaml_SEQUENCE_START_EVENT)
// 	for p.peek() != yaml_SEQUENCE_END_EVENT {
// 		n.children = append(n.children, p.parse())
// 	}
// 	p.expect(yaml_SEQUENCE_END_EVENT)
// 	return n
// }

// func (p *parser) document() *node {
// 	n := p.node(documentNode)
// 	n.anchors = make(map[string]*node)
// 	p.doc = n
// 	p.expect(yaml_DOCUMENT_START_EVENT)
// 	n.children = append(n.children, p.parse())
// 	p.expect(yaml_DOCUMENT_END_EVENT)
// 	return n
// }
// func (d *decoder) unmarshal(n *node, out reflect.Value) (good bool) {
// 	d.decodeCount++
// 	if d.aliasDepth > 0 {
// 		d.aliasCount++
// 	}
// 	if d.aliasCount > 100 && d.decodeCount > 1000 && float64(d.aliasCount)/float64(d.decodeCount) > allowedAliasRatio(d.decodeCount) {
// 		failf("document contains excessive aliasing")
// 	}
// 	switch n.kind {
// 	case documentNode:
// 		return d.document(n, out)
// 	case aliasNode:
// 		return d.alias(n, out)
// 	}
// 	out, unmarshaled, good := d.prepare(n, out)
// 	if unmarshaled {
// 		return good
// 	}
// 	switch n.kind {
// 	case scalarNode:
// 		good = d.scalar(n, out)
// 	case mappingNode:
// 		good = d.mapping(n, out)
// 	case sequenceNode:
// 		good = d.sequence(n, out)
// 	default:
// 		panic("internal error: unknown node kind: " + strconv.Itoa(n.kind))
// 	}
// 	return good
// }

// type TypeError struct {
// 	Errors []string
// }

// type decoder struct {
// 	doc     *node
// 	aliases map[*node]bool
// 	mapType reflect.Type
// 	terrors []string
// 	strict  bool

// 	decodeCount int
// 	aliasCount  int
// 	aliasDepth  int
// }

// func yaml_event_delete(event *yaml_event_t) {
// 	*event = yaml_event_t{}
// }

// func yaml_parser_delete(parser *yaml_parser_t) {
// 	*parser = yaml_parser_t{}
// }

// func yaml_parser_initialize(parser *yaml_parser_t) bool {
// 	*parser = yaml_parser_t{
// 		raw_buffer: make([]byte, 0, input_raw_buffer_size),
// 		buffer:     make([]byte, 0, input_buffer_size),
// 	}
// 	return true
// }

// func yaml_parser_set_input_string(parser *yaml_parser_t, input []byte) {
// 	if parser.read_handler != nil {
// 		panic("must set the input source only once")
// 	}
// 	parser.read_handler = yaml_string_read_handler
// 	parser.input = input
// 	parser.input_pos = 0
// }

// func (d *decoder) alias(n *node, out reflect.Value) (good bool) {
// 	if d.aliases[n] {
// 		// TODO this could actually be allowed in some circumstances.
// 		failf("anchor '%s' value contains itself", n.value)
// 	}
// 	d.aliases[n] = true
// 	d.aliasDepth++
// 	good = d.unmarshal(n.alias, out)
// 	d.aliasDepth--
// 	delete(d.aliases, n)
// 	return good
// }

// func (p *parser) scalar() *node {
// 	n := p.node(scalarNode)
// 	n.value = string(p.event.value)
// 	n.tag = string(p.event.tag)
// 	n.implicit = p.event.implicit
// 	p.anchor(n, p.event.anchor)
// 	p.expect(yaml_SCALAR_EVENT)
// 	return n
// }

// func (p *parser) anchor(n *node, anchor []byte) {
// 	if anchor != nil {
// 		p.doc.anchors[string(anchor)] = n
// 	}
// }
// type node struct {
// 	kind         int
// 	line, column int
// 	tag          string
// 	// For an alias node, alias holds the resolved alias.
// 	alias    *node
// 	value    string
// 	implicit bool
// 	children []*node
// 	anchors  map[string]*node
// }
// func (p *parser) node(kind int) *node {
// 	return &node{
// 		kind:   kind,
// 		line:   p.event.start_mark.line,
// 		column: p.event.start_mark.column,
// 	}
// }

// func (p *parser) expect(e yaml_event_type_t) {
// 	if p.event.typ == yaml_NO_EVENT {
// 		if !yaml_parser_parse(&p.parser, &p.event) {
// 			p.fail()
// 		}
// 	}
// 	if p.event.typ == yaml_STREAM_END_EVENT {
// 		failf("attempted to go past the end of stream; corrupted value?")
// 	}
// 	if p.event.typ != e {
// 		p.parser.problem = fmt.Sprintf("expected %s event but got %s", e, p.event.typ)
// 		p.fail()
// 	}
// 	yaml_event_delete(&p.event)
// 	p.event.typ = yaml_NO_EVENT
// }

// type yamlError struct {
// 	err error
// }

// const (
// 	// An empty event.
// 	yaml_NO_EVENT yaml_event_type_t = iota

// 	yaml_STREAM_START_EVENT   // A STREAM-START event.
// 	yaml_STREAM_END_EVENT     // A STREAM-END event.
// 	yaml_DOCUMENT_START_EVENT // A DOCUMENT-START event.
// 	yaml_DOCUMENT_END_EVENT   // A DOCUMENT-END event.
// 	yaml_ALIAS_EVENT          // An ALIAS event.
// 	yaml_SCALAR_EVENT         // A SCALAR event.
// 	yaml_SEQUENCE_START_EVENT // A SEQUENCE-START event.
// 	yaml_SEQUENCE_END_EVENT   // A SEQUENCE-END event.
// 	yaml_MAPPING_START_EVENT  // A MAPPING-START event.
// 	yaml_MAPPING_END_EVENT    // A MAPPING-END event.
// )

// var eventStrings = []string{
// 	yaml_NO_EVENT:             "none",
// 	yaml_STREAM_START_EVENT:   "stream start",
// 	yaml_STREAM_END_EVENT:     "stream end",
// 	yaml_DOCUMENT_START_EVENT: "document start",
// 	yaml_DOCUMENT_END_EVENT:   "document end",
// 	yaml_ALIAS_EVENT:          "alias",
// 	yaml_SCALAR_EVENT:         "scalar",
// 	yaml_SEQUENCE_START_EVENT: "sequence start",
// 	yaml_SEQUENCE_END_EVENT:   "sequence end",
// 	yaml_MAPPING_START_EVENT:  "mapping start",
// 	yaml_MAPPING_END_EVENT:    "mapping end",
// }

