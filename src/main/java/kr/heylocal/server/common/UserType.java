package kr.heylocal.server.common;

public enum UserType {
    UNKNOWN("unknown"),
    TRAVELER("traveler"),
    LOCAL("local"),
    SANCTIONED_TRAVELER("sanctionedTraveler"),
    SANCTIONED_LOCAL("sanctionedLocal"),
    DELETED_TRAVELER("deletedTraveler"),
    DELETED_LOCAL("deletedLocal");
    private final String name;
    UserType(String name) {
        this.name = name;
    }
    public static UserType fromName(String value) {
        if (value == null) return UNKNOWN;
        for (UserType type : values()) {
            if (type.name.equalsIgnoreCase(value)) {
                return type;
            }
        }
        return UNKNOWN;
    }
    public String getName() {
        return name;
    }
    // 탈퇴 상태 변환 로직
    public UserType toDeleted() {
        return switch (this) {
            case TRAVELER, SANCTIONED_TRAVELER, DELETED_TRAVELER -> DELETED_TRAVELER;
            case LOCAL, SANCTIONED_LOCAL, DELETED_LOCAL -> DELETED_LOCAL;
            default -> DELETED_TRAVELER;
        };
    }
}
