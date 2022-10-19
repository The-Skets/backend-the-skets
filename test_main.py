from unittest import TestCase, main

from main import app


class Test(TestCase):
    def setUp(self):
        self.ctx = app.app_context()
        self.ctx.push()
        self.client = app.test_client()

    def tearDown(self):
        self.ctx.pop()

    def test_get_performances(self):
        response = self.client.get("/v1/get_performances")

        assert response.status_code == 200
        assert response.is_json
        assert response.json[0]["quality"] == "480p"

    def test_v1_private_sign_in(self):
        response = self.client.post("/v1/get_performances", data=())

if __name__ == "__main__":
    main()
