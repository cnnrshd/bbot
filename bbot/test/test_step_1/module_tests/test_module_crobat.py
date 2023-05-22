from .base import ModuleTestBase


class TestCrobat(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://sonar.omnisint.io/subdomains/blacklanternsecurity.com",
            json=["asdf.blacklanternsecurity.com"],
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
