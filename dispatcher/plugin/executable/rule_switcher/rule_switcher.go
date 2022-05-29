//     Copyright (C) 2020-2021, IrineSistiana
//
//     This file is part of mosdns.
//
//     mosdns is free software: you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     mosdns is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.

package rule_switcher

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v3/dispatcher/handler"
	"github.com/IrineSistiana/mosdns/v3/dispatcher/pkg/rule_switcher"
)

const PluginType = "rule_switcher"

func init() {
	handler.RegInitFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
	Rules []*rule_switcher.RuleArgs `yaml:"rules"`
}

var _ handler.ExecutablePlugin = (*switcherPlugin)(nil)

type switcherPlugin struct {
	*handler.BP
	s rule_switcher.Switcher
}

// Exec implements handler.Executable.
func (s *switcherPlugin) Exec(ctx context.Context, qCtx *handler.Context, next handler.ExecutableChainNode) error {
	return s.s.Exec(ctx, qCtx, next)
}

// Init is a handler.NewPluginFunc.
func Init(bp *handler.BP, args interface{}) (p handler.Plugin, err error) {
	a := args.(*Args)
	s := rule_switcher.Switcher{}
	if err := s.Load(a.Rules); err != nil {
		return nil, fmt.Errorf("failed to load rules, %w", err)
	}
	return &switcherPlugin{
		BP: bp,
		s:  s,
	}, nil
}
