REBAR ?= rebar3
PROJECT := enotify

.PHONY: compile clean distclean xref dialyzer dialyze linter lint test check-syntax

all: compile

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

distclean:
	make -C c_src clean
	rm -rf _build

xref:
	@$(REBAR) xref

dialyze:
	@$(REBAR) dialyzer

lint:
	@$(REBAR) as lint lint

test:
	@$(REBAR) eunit --verbose --cover
	@$(REBAR) cover --verbose

check-syntax:
	make -C c_src check-syntax
