def get_enter_area_id(info, dungeon_type: int, is_tw: bool) -> int:
    """TW tracks normal (1) and special (2) dungeon areas separately."""
    if not is_tw:
        return info.enter_area_id
    for area in info.enter_area_info_list or []:
        if area.dungeon_type == dungeon_type:
            return area.dungeon_area_id or 0
    return 0


def get_rest_challenge_count(info, dungeon_type: int, is_tw: bool) -> int:
    if not is_tw:
        return info.rest_challenge_count[0].count
    for count in info.rest_challenge_count or []:
        if count.dungeon_type == dungeon_type:
            return count.count or 0
    return 0
