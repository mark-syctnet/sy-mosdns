package rule_switcher

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v3/dispatcher/handler"
	"github.com/IrineSistiana/mosdns/v3/dispatcher/pkg/executable_seq"
	"github.com/IrineSistiana/mosdns/v3/dispatcher/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v3/dispatcher/pkg/matcher/msg_matcher"
	"github.com/IrineSistiana/mosdns/v3/dispatcher/pkg/matcher/netlist"
	"go.uber.org/zap"
	"strings"
)

var nopLogger = zap.NewNop()

type Switcher struct {
	Rules  []*Rule
	Logger *zap.Logger
}

type Rule struct {
	m handler.Matcher
	d handler.Executable
}

func (s *Switcher) Exec(ctx context.Context, qCtx *handler.Context, next handler.ExecutableChainNode) error {
	for i, rule := range s.Rules {
		ok, err := rule.m.Match(ctx, qCtx)
		if err != nil {
			return fmt.Errorf("#%d matcher err: %w", i, err)
		}
		if ok {
			return rule.d.Exec(ctx, qCtx, next)
		}
	}
	return handler.ExecChainNode(ctx, qCtx, next)
}

func (s *Switcher) logger() *zap.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return nopLogger
}

const (
	RuleTypeQName = "qname"
	RuleTypeIP    = "ip"
	RuleDefault   = "default"
)

type RuleArgs struct {
	Type string      `yaml:"type"`
	Args string      `yaml:"args"`
	Exec interface{} `yaml:"exec"`
}

func (s *Switcher) Load(ras []*RuleArgs) error {
	for i, ra := range ras {
		r, err := s.parseRuleStr(ra)
		if err != nil {
			return fmt.Errorf("failed to parse rule #%d, %w", i, err)
		}
		s.Rules = append(s.Rules, r)
	}
	return nil
}

func (s *Switcher) parseRuleStr(ra *RuleArgs) (*Rule, error) {
	var neg bool
	if strings.HasPrefix(ra.Type, "!") {
		ra.Type = strings.TrimPrefix(ra.Type, "!")
		neg = true
	}

	var m handler.Matcher
	switch ra.Type {
	case RuleDefault:
		m = defaultMatcher{}
	case RuleTypeQName:
		dm := domain.NewMixMatcher[struct{}]()
		if err := domain.Load[struct{}](dm, ra.Args, nil); err != nil {
			return nil, err
		}
		m = msg_matcher.NewQNameMatcher(dm)
	case RuleTypeIP:
		ipList := netlist.NewList()
		if err := netlist.Load(ipList, ra.Args); err != nil {
			return nil, err
		}
		m = msg_matcher.NewAAAAAIPMatcher(ipList)
	default:
		return nil, fmt.Errorf("unsupported rule type [%s]", ra.Type)
	}

	if neg {
		m = executable_seq.NagateMatcher(m)
	}

	execNode, err := executable_seq.ParseExecutableNode(ra.Exec, s.logger())
	if err != nil {
		return nil, fmt.Errorf("failed to parse exec sequence, %w", err)
	}
	return &Rule{
		m: m,
		d: execNode,
	}, nil
}

type defaultMatcher struct{}

func (d defaultMatcher) Match(ctx context.Context, qCtx *handler.Context) (matched bool, err error) {
	return true, err
}
