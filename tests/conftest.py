from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx
import pytest

from aae_a2a.buyer import BuyerAgent
from aae_a2a.challenge import utc_now
from aae_a2a.server import create_supplier_app
from aae_a2a.testkeys import demo_resolver, did_of, issue_supplier_aae

BASE_URL = "http://supplier.example"
DOMAINS = ["supplier.example"]


def run(coro):
    return asyncio.run(coro)


@dataclass
class Env:
    app: object
    executor: object

    def buyer(self, name: str = "buyer") -> BuyerAgent:
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url=BASE_URL)
        return BuyerAgent(BASE_URL, name=name, httpx_client=client)

    async def discovered(self, name: str = "buyer") -> BuyerAgent:
        b = self.buyer(name)
        await b.discover()
        return b


@pytest.fixture
def env() -> Env:
    app, _card, executor = create_supplier_app(
        BASE_URL, resolver=demo_resolver(), accepted_issuers=[did_of("issuer")],
        own_aae=issue_supplier_aae(utc_now()))
    return Env(app=app, executor=executor)
