import copy
from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock

from faker import Faker
import lister

faker = Faker()


class TestListerThreading(TestCase):
    def get_instace(self, **kwargs):
        config = {
            "profile": faker.word(),
            "region": faker.word(),
            "regions": [faker.word() for _ in range(4)],
            "arg_list": {faker.word(): faker.word() for _ in range(3)}
        }
        config.update(kwargs)
        lister_threading = lister.ListerThreading(**config)

        return config, lister_threading

    def test_init(self):
        kwargs, lister_threading = self.get_instace()
        expected_config = copy.deepcopy(kwargs)
        expected_config.update({"args": kwargs["arg_list"]})
        del (expected_config["arg_list"])

        assert lister_threading.config == expected_config

    def test_run_ok(self):
        params = {
            "arg_list": {
                "list": faker.word()
            }
        }
        kwargs, lister_threading = self.get_instace(**params)
        kwargs["args"] = params["arg_list"]
        del kwargs["arg_list"]

        all_mocked = (faker.word() for _ in range(4))
        instances_mock = Mock()
        instances_mock.all = Mock(return_value=all_mocked)
        get_ec2_mocked = Mock()
        get_ec2_mocked.instances = instances_mock
        console_mocked = Mock()
        console_mocked.log = Mock()
        expected_msg = (
            f"Found [bold underline white on black]4[/] instances on"
            f"region [bold underline white on black]{kwargs['region']}[/]"
        )
        with patch.object(lister, "get_ec2", return_value=get_ec2_mocked) as e1:
            with patch.object(lister, "console", console_mocked) as e2:
                lister_threading.run()

                e1.assert_called_with(**kwargs)
                e2.log.assert_called_with(expected_msg, style="bold green")

    def test_run_fail(self):
        kwargs, lister_threading = self.get_instace()
        get_ec2_mocked = Mock()
        console_mocked = Mock()
        console_mocked.log = Mock()

        with patch.object(lister, "get_ec2", return_value=get_ec2_mocked) as e1:
            with patch.object(lister, "console", console_mocked) as e2:
                lister_threading.run()

                e1.assert_not_called()
                e2.log.assert_not_called()

    def test_start(self):
        start_mocked = Mock()
        with patch.object(lister.Thread, "start", start_mocked) as e1:
            kwargs, lister_threading = self.get_instace()
            lister_threading.start()

            e1.assert_called()
