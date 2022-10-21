from unittest import TestCase, main
from flask import session
from main import app
from config import env


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
        with self.client:
            response = self.client.post("/v1/private/sign_in", json={
                "username": env["TEST_USERNAME"],
                "password": env["TEST_PASSWORD"]
            })

            assert response.status_code == 200
            assert response.json["status"] == "success"
            assert session["logged_in"] is True
            assert session["profile"]["name"] == "carter"

    # def test_v1_private_sign_up(self):
    #     response = self.client.post("/v1/private/sign_up", json={
    #         "username": env["TEST_SIGNUP_USERNAME"],
    #         "password": env["TEST_SIGNUP_PASSWORD"],
    #         "email": env["TEST_SIGNUP_EMAIL"]
    #     })
    #
    #     assert response.status_code == 200
    #     assert response.json["status"] == "success"
    #     assert session["logged_in"] is True
    #
    #     response = self.client.post("/v1/private/sign_up", json={
    #         "username": "default",
    #         "password": env["TEST_SIGNUP_PASSWORD"],
    #         "email": env["TEST_SIGNUP_EMAIL"]
    #     })
    #
    #     assert response.status_code != 200
    #     assert response.json["status"] == "failure"
    #
    #



if __name__ == "__main__":
    main()
