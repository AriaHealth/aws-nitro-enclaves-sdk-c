from actions import __dir__, __prefix__, ActionsDict, ActionsEnum


def test_action():
    for action in __dir__():
        assert action in ActionsDict.keys()
        assert getattr(ActionsEnum, action[len(__prefix__) :]) == ActionsDict[action]
