import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet, Platform } from 'react-native';
import Svg, { Path } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';

const SettingsMenuItem = ({ icon, label, onPress }) => (
  <TouchableOpacity style={styles.menuItem} onPress={onPress} activeOpacity={0.7}>
    <View style={styles.menuItemLeft}>
      {icon}
      <Text style={styles.menuItemLabel}>{label}</Text>
    </View>
    <Svg width={8} height={14} viewBox="0 0 8 14" fill="none">
      <Path
        d="M1 13L7 7L1 1"
        stroke="black"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </Svg>
  </TouchableOpacity>
);

export default function HelpSupport() {
  const navigation = useNavigation();

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Svg width={8} height={24} viewBox="0 0 8 14" fill="none">
            <Path
              d="M7 1L1 7L7 13"
              stroke="black"
              strokeWidth="1.7"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </Svg>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Help & Support</Text>
        <View style={{ width: 24 }} />
      </View>

      {/* Menu Items */}
      <View style={styles.menuContainer}>
        {/* FAQ’s */}
        <SettingsMenuItem
          icon={
            <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
              <Path
                d="M12 15.9995V16.0095M12 12.9995C12.4498 13.0009 12.8868 12.8506 13.2407 12.573C13.5945 12.2953 13.8444 11.9065 13.95 11.4693C14.0557 11.0322 14.0109 10.5722 13.8229 10.1636C13.6349 9.755 13.3147 9.4217 12.914 9.21752C12.5162 9.01373 12.0611 8.95054 11.6228 9.03824C11.1845 9.12593 10.7888 9.35935 10.5 9.70052M19.875 6.26959C20.575 6.66759 21.005 7.41259 21 8.21759V15.5016C21 16.3106 20.557 17.0566 19.842 17.4496L13.092 21.7196C12.7574 21.9033 12.3818 21.9996 12 21.9996C11.6182 21.9996 11.2426 21.9033 10.908 21.7196L4.158 17.4496C3.80817 17.2584 3.51612 16.9768 3.31241 16.6341C3.1087 16.2914 3.0008 15.9003 3 15.5016V8.21659C3 7.40759 3.443 6.66259 4.158 6.26959L10.908 2.28959C11.2525 2.09963 11.6396 2 12.033 2C12.4264 2 12.8135 2.09963 13.158 2.28959L19.908 6.26959H19.875Z"
                stroke="#0E0E0E"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </Svg>
          }
          label="FAQ’s"
          onPress={() => navigation.navigate('Faq')}
        />

        {/* Feedback */}
        <SettingsMenuItem
          icon={
            <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
              <Path
                d="M9 5H7C6.46957 5 5.96086 5.21071 5.58579 5.58579C5.21071 5.96086 5 6.46957 5 7V19C5 19.5304 5.21071 20.0391 5.58579 20.4142C5.96086 20.7893 6.46957 21 7 21H17C17.5304 21 18.0391 20.7893 18.4142 20.4142C18.7893 20.0391 19 19.5304 19 19V7C19 6.46957 18.7893 5.96086 18.4142 5.58579C18.0391 5.21071 17.5304 5 17 5H15M9 5C9 4.46957 9.21071 3.96086 9.58579 3.58579C9.96086 3.21071 10.4696 3 11 3H13C13.5304 3 14.0391 3.21071 14.4142 3.58579C14.7893 3.96086 15 4.46957 15 5M9 5C9 5.53043 9.21071 6.03914 9.58579 6.41421C9.96086 6.78929 10.4696 7 11 7H13C13.5304 7 14.0391 6.78929 14.4142 6.41421C14.7893 6.03914 15 5.53043 15 5M9 12H15M9 16H15"
                stroke="#0E0E0E"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </Svg>
          }
          label="Feedback"
          onPress={() => navigation.navigate('Feedback')}
        />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFFFF',
    paddingTop: 39,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 12,
    columnGap: 25, // Added gap here
    marginLeft:9,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '500',
    color: '#0C0D11',
    fontFamily: 'Poppins',
  },
  menuContainer: {
    paddingTop: 24,
  },
  menuItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 20,
    paddingVertical: 16,
  },
  menuItemLeft: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  menuItemLabel: {
    marginLeft: 16,
    fontSize: 16,
    fontWeight: '500',
    color: '#2C2C2C',
    fontFamily: 'Poppins',
  },
});