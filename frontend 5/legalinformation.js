import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  Platform,
} from 'react-native';
import Svg, { Path } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';

const LegalMenuItem = ({ label, onPress }) => (
  <TouchableOpacity style={styles.item} onPress={onPress} activeOpacity={0.7}>
    <Text style={styles.itemLabel}>{label}</Text>
    <Svg width={8} height={12} viewBox="0 0 8 14" fill="none">
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

export default function Legal() {
  const navigation = useNavigation();

  const goTo = screen => {
    navigation.navigate(screen);
  };

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Svg width={8} height={24} viewBox="0 0 8 14" fill="none">
            <Path
              d="M7 1L1 7L7 13"
              stroke="#2C2C2C"
              strokeWidth="1.7"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </Svg>
        </TouchableOpacity>
        <Text style={styles.title}>Legal Information</Text>
      </View>

      {/* List */}
      <ScrollView contentContainerStyle={styles.list}>
        <LegalMenuItem
          label="Privacy Policy"
          onPress={() => goTo('PrivacyPolicy')}
        />
        <LegalMenuItem
          label="Terms & Conditions"
          onPress={() => goTo('TermsConditions')}
        />
        <LegalMenuItem
          label="Open Source Licenses"
          onPress={() => goTo('Opensource')}
        />
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFF',
    paddingTop: 50, // Corrected padding
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 17, // This is the gap
    paddingHorizontal: 20,
    paddingBottom: 4,
    marginLeft:9,
  },
  title: {
    fontSize: 20,
    fontWeight: '500',
    color: '#0C0D11',
    fontFamily: 'Poppins',
    lineHeight: 26,
    marginLeft:10,
  },
  list: {
    paddingTop: 24,
  },
  item: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#E6E6E6',
  },
  itemLabel: {
    flex: 1,
    fontSize: 16,
    fontWeight: '400',
    color: '#2C2C2C',
    fontFamily: 'Poppins',
  },
});