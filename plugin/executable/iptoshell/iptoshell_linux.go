//go:build linux

/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package iptoshell

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v4/coremain"
	"github.com/IrineSistiana/mosdns/v4/pkg/executable_seq"
	"github.com/IrineSistiana/mosdns/v4/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"net/netip"
	"os/exec"
	"time"
	"syscall"
)

var _ coremain.ExecutablePlugin = (*iptoshellPlugin)(nil)

type iptoshellPlugin struct {
	*coremain.BP
	args *Args
}

func ShellCmdTimeout(timeout int, cmd string, args ...string) (e error) {
    if len(cmd) == 0 {
        e = fmt.Errorf("cannot run a empty command")
        return
    } 
    command := exec.Command(cmd, args...)
    command.Start()
    done := make(chan error)
    go func() { done <- command.Wait() }()
    after := time.After(time.Duration(timeout) * time.Second)
    select {
    case <-after:
        command.Process.Signal(syscall.SIGINT)
        time.Sleep(time.Second)
        command.Process.Kill()
    case <-done:
    }
    return
}

func newiptoshellPlugin(bp *coremain.BP, args *Args) (*iptoshellPlugin, error) {
	if args.Mask4 == 0 {
		args.Mask4 = 24
	}
	if args.Mask6 == 0 {
		args.Mask6 = 32
	}


	return &iptoshellPlugin{
		BP:   bp,
		args: args,
	}, nil
}

func (p *iptoshellPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	r := qCtx.R()
	if r != nil {
		er := p.addIPtoshell(r)
		if er != nil {
			p.L().Warn("failed to add response IP to shell", qCtx.InfoField(), zap.Error(er))
		}
	}

	return executable_seq.ExecChainNode(ctx, qCtx, next)
}


func (p *iptoshellPlugin) addIPtoshell(r *dns.Msg) error {
	for i := range r.Answer {
		switch rr := r.Answer[i].(type) {
		case *dns.A:
			if len(p.args.SetName4) == 0 {
				continue
			}
			addr, ok := netip.AddrFromSlice(rr.A.To4())
			if !ok {
				return fmt.Errorf("iptoshell invalid A record with ip: %s", rr.A)
			}
			err := ShellCmdTimeout(5, p.args.SetName4, netip.PrefixFrom(addr, p.args.Mask4).String())
			if err != nil {
			      return fmt.Errorf(" RUN iptoshell invalid  A record with ip: %s", rr.A)
			}    
			
			

		case *dns.AAAA:
			if len(p.args.SetName6) == 0 {
				continue
			}
			addr, ok := netip.AddrFromSlice(rr.AAAA.To16())
			if !ok {
				return fmt.Errorf("invalid AAAA record with ip: %s", rr.AAAA)
			}
			err := ShellCmdTimeout(5, p.args.SetName6, netip.PrefixFrom(addr, p.args.Mask6).String())
			if err != nil {
			     return fmt.Errorf("iptoshell AAAA record with ip: %s", rr.AAAA)
			} 
			
			
		default:
			continue
		}
	}

	return nil
}
