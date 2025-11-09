import React, { useState, useRef } from 'react';
import { View, Text, StyleSheet, SafeAreaView, TouchableOpacity, TextInput, ScrollView, Animated } from 'react-native';
import { Svg, Path } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';

// Reusable Components
const NavIconsBack = () => (
  <View style={headerStyles.navIconsBackContainer}>
    <Svg style={headerStyles.vector} width="8" height="14" viewBox="0 0 8 14" fill="none">
      <Path d="M7 1L1 7L7 13" stroke="#2C2C2C" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </Svg>
  </View>
);

const Header = ({ title, onBackPress }) => (
  <View style={headerStyles.header}>
    <View style={headerStyles.headerContent}>
      <TouchableOpacity onPress={onBackPress}>
        <NavIconsBack />
      </TouchableOpacity>
      <Text style={headerStyles.headerTitle}>{title}</Text>
    </View>
  </View>
);

const Chip = ({ text, isActive, onPress }) => (
  <TouchableOpacity onPress={() => onPress(text)} style={[chipStyles.chipContainer, isActive && chipStyles.chipActive]}>
    <Text style={chipStyles.chipText}>
      {text}
    </Text>
  </TouchableOpacity>
);

const TabBar = ({ activeTab, onTabPress }) => (
  <View style={tabBarStyles.navigationTopTabsBarContainer}>
    <TouchableOpacity
      style={[tabBarStyles.tab, activeTab === 'TOEFL' && tabBarStyles.activeTab]}
      onPress={() => onTabPress('TOEFL')}
    >
      <Text style={[tabBarStyles.tabText, activeTab === 'TOEFL' && tabBarStyles.activeTabText]}>TOEFL</Text>
    </TouchableOpacity>
    <TouchableOpacity
      style={[tabBarStyles.tab, activeTab === 'IELTS' && tabBarStyles.activeTab]}
      onPress={() => onTabPress('IELTS')}
    >
      <Text style={[tabBarStyles.tabText, activeTab === 'IELTS' && tabBarStyles.activeTabText]}>IELTS</Text>
    </TouchableOpacity>
    <TouchableOpacity
      style={[tabBarStyles.tab, activeTab === 'CEFR' && tabBarStyles.activeTab]}
      onPress={() => onTabPress('CEFR')}
    >
      <Text style={[tabBarStyles.tabText, activeTab === 'CEFR' && tabBarStyles.activeTabText]}>CEFR</Text>
    </TouchableOpacity>
  </View>
);

const Toggle = ({ value, onValueChange }) => {
  const animatedValue = useRef(new Animated.Value(value ? 1 : 0)).current;

  React.useEffect(() => {
    Animated.timing(animatedValue, {
      toValue: value ? 1 : 0,
      duration: 250,
      useNativeDriver: false,
    }).start();
  }, [value, animatedValue]);

  const knobPosition = animatedValue.interpolate({
    inputRange: [0, 1],
    outputRange: [2, 17],
  });

  const backgroundColor = animatedValue.interpolate({
    inputRange: [0, 1],
    outputRange: ['rgba(120, 120, 128, 0.16)', '#FFA364'],
  });

  return (
    <TouchableOpacity onPress={onValueChange} activeOpacity={0.8}>
      <Animated.View style={[toggleStyles.toggleContainer, { backgroundColor }]}>
        <Animated.View style={[toggleStyles.knob, { marginLeft: knobPosition }]} />
      </Animated.View>
    </TouchableOpacity>
  );
};

// Main Screen Component
const PersonalizationMemoryScreen = () => {
  const navigation = useNavigation();
  const [isMemoryEnabled, setIsMemoryEnabled] = useState(false);
  const toggleMemorySwitch = () => setIsMemoryEnabled(previousState => !previousState);

  const [promptText, setPromptText] = useState('');

  const [activeRecentTag, setActiveRecentTag] = useState(null);
  const [activeLanguageTag, setActiveLanguageTag] = useState('TOEFL');

  const handleRecentTagPress = (tagText) => {
    setActiveRecentTag(activeRecentTag === tagText ? null : tagText);
  };

  const handleLanguageTagPress = (tagText) => {
    setActiveLanguageTag(activeLanguageTag === tagText ? null : tagText);
  };

  return (
    <SafeAreaView style={styles.container}>
      <Header title="Personalization & Memory" onBackPress={() => navigation.goBack()} />

      <ScrollView contentContainerStyle={styles.scrollContent}>
        {/* Tone & Style Memory Section */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Tone & Style Memory</Text>
          <View style={styles.rowBetween}>
            <Text style={styles.label}>Memory</Text>
            <Toggle value={isMemoryEnabled} onValueChange={toggleMemorySwitch} />
          </View>
          <TouchableOpacity style={styles.clearMemoryButton}>
            <Text style={styles.clearMemoryButtonText}>Clear Memory</Text>
          </TouchableOpacity>
        </View>

        {/* Recent Phrases & Styles Section */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Recent Phrases & Styles</Text>
          <View style={styles.tagContainer}>
            <Chip text="Formal" isActive={activeRecentTag === "Formal"} onPress={handleRecentTagPress} />
            <Chip text="Friendly" isActive={activeRecentTag === "Friendly"} onPress={handleRecentTagPress} />
            <Chip text="Simple" isActive={activeRecentTag === "Simple"} onPress={handleRecentTagPress} />
            <Chip text="Concise" isActive={activeRecentTag === "Concise"} onPress={handleRecentTagPress} />
          </View>
          <TouchableOpacity>
            <Text style={styles.seeAllText}>See All</Text>
          </TouchableOpacity>
        </View>

        {/* Prompt Editor Section */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Prompt Editor</Text>
          <TextInput
            style={promptEditorStyles.promptEditorInput}
            multiline
            placeholder="Enter your prompt here..."
            placeholderTextColor="#4A4A4A"
            value={promptText}
            onChangeText={setPromptText}
          />
          <View style={styles.buttonRow}>
            <TouchableOpacity style={buttonStyles.secondaryButton}>
              <Text style={buttonStyles.secondaryButtonText}>Reset Default</Text>
            </TouchableOpacity>
            <TouchableOpacity style={buttonStyles.primaryButton}>
              <Text style={buttonStyles.primaryButtonText}>Save Prompt</Text>
            </TouchableOpacity>
          </View>
        </View>

        {/* Language Test Mode Section */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Language Test Mode</Text>
          <TabBar activeTab={activeLanguageTag} onTabPress={handleLanguageTagPress} />
          <Text style={styles.progressLabel}>Progress</Text>
          <View style={styles.progressBarBackground}>
            <View style={styles.progressBarFill} />
          </View>
          <Text style={styles.progressPercentage}>20%</Text>
          <View style={styles.resetDataButtonWrapper}>
            <TouchableOpacity style={styles.resetDataButton}>
              <Text style={styles.resetDataButtonText}>Reset Data</Text>
            </TouchableOpacity>
          </View>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
};

// Styles
const headerStyles = StyleSheet.create({
  header: {
    paddingTop: 28,
    paddingHorizontal: 20,
    marginBottom: 20,
    paddingLeft: 7,
    marginLeft: 9, // Added style for the left margin
  },
  headerContent: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 8,
  },
  navIconsBackContainer: {
    height: 36,
    width: 36,
    justifyContent: 'center',
    alignItems: 'center',
  },
  vector: {
    position: 'relative',
  },
  headerTitle: {
    color: '#0C0D11',
    fontSize: 20,
    fontWeight: '500',
  },
});

const chipStyles = StyleSheet.create({
  chipContainer: {
    borderStyle: "solid",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderWidth: 1,
    borderColor: "rgba(44, 44, 44, 1)",
    borderRadius: 48,
  },
  chipText: {
    textAlign: "left",
    color: "rgba(44, 44, 44, 1)",
    fontSize: 12,
    fontWeight: '500',
  },
  chipActive: {
    backgroundColor: '#FFA364',
    borderColor: '#FFA364',
  },
  chipTextActive: {
    color: '#FFFFFF',
  },
});

const tabBarStyles = StyleSheet.create({
  navigationTopTabsBarContainer: {
    alignSelf: "stretch",
    flexShrink: 0,
    borderTopWidth: 0,
    borderRightWidth: 0,
    borderBottomWidth: 1,
    borderLeftWidth: 0,
    borderStyle: "solid",
    backgroundColor: "#FFFFFF",
    flexDirection: "row",
    alignItems: "flex-start",
    columnGap: 20,
    paddingHorizontal: 32,
    paddingVertical: 0,
    borderColor: "rgba(239, 241, 245, 1)",
  },
  tab: {
    paddingVertical: 16,
  },
  activeTab: {
    borderBottomWidth: 3,
    borderBottomColor: "#1C1B1F",
  },
  tabText: {
    textAlign: "center",
    color: "#A09CAB",
    fontSize: 14,
    fontWeight: '600',
  },
  activeTabText: {
    color: "#1C1B1F",
  }
});

const toggleStyles = StyleSheet.create({
  toggleContainer: {
    height: 23,
    width: 38,
    borderRadius: 75,
    justifyContent: 'center',
  },
  knob: {
    height: 19,
    width: 19,
    backgroundColor: 'rgba(255, 255, 255, 1)',
    shadowColor: 'rgba(0, 0, 0, 0.06)',
    shadowOffset: { width: 0, height: 2.25 },
    shadowRadius: 0.75,
    borderRadius: 75,
  },
});

const promptEditorStyles = StyleSheet.create({
  promptEditorInput: {
    position: "relative",
    alignSelf: "stretch",
    flexShrink: 0,
    height: 100,
    paddingTop: 12,
    paddingBottom: 12,
    paddingLeft: 18,
    paddingRight: 16,
    borderStyle: "solid",
    borderWidth: 1,
    borderColor: "rgba(44, 44, 44, 1)",
    borderRadius: 16,
    fontSize: 12,
    color: "rgba(74, 74, 74, 1)",
    textAlignVertical: 'top',
  }
});

const buttonStyles = StyleSheet.create({
  primaryButton: {
    flex: 1,
    backgroundColor: '#0C0D11',
    paddingVertical: 14,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
    height: 52,
  },
  primaryButtonText: {
    color: '#F6F6F8',
    fontSize: 17,
    fontWeight: '700',
  },
  secondaryButton: {
    flex: 1,
    backgroundColor: '#E0E0E0',
    paddingVertical: 14,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
    height: 52,
  },
  secondaryButtonText: {
    color: '#2C2C2C',
    fontSize: 17,
    fontWeight: '700',
  },
});

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFFFF',
    paddingTop:18,
  },
  scrollContent: {
    paddingHorizontal: 20,
    paddingBottom: 20,
  },
  section: {
    marginBottom: 25,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#0C0D11',
    marginBottom: 15,
  },
  rowBetween: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 15,
  },
  label: {
    fontSize: 16,
    color: '#2C2C2C',
  },
  clearMemoryButton: {
    backgroundColor: '#EDEDED',
    paddingVertical: 10,
    paddingHorizontal: 15,
    borderRadius: 8,
    alignSelf: 'flex-start',
  },
  clearMemoryButtonText: {
    color: '#2C2C2C',
    fontSize: 14,
    fontWeight: '500',
  },
  tagContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    marginBottom: 15,
    gap: 8,
  },
  seeAllText: {
    color: '#2C2C2C',
    fontSize: 14,
    textDecorationLine: 'underline',
    alignSelf: 'flex-start',
    marginTop: 5,
  },
  buttonRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: 10,
    marginTop: 15,
  },
  progressLabel: {
    fontSize: 16,
    color: '#2C2C2C',
    marginBottom: 10,
    marginTop: 15,
  },
  progressBarBackground: {
    height: 8,
    backgroundColor: '#EDEDED',
    borderRadius: 4,
    overflow: 'hidden',
    width: '100%',
    marginBottom: 5,
  },
  progressBarFill: {
    width: '20%',
    height: '100%',
    backgroundColor: '#FFA364',
    borderRadius: 4,
  },
  progressPercentage: {
    fontSize: 14,
    color: '#2C2C2C',
    alignSelf: 'flex-end',
    marginBottom: 20,
  },
  resetDataButtonWrapper: {
    width: '100%',
    alignItems: 'center',
    marginBottom: 20,
  },
  resetDataButton: {
    height: 43,
    width: 130,
    backgroundColor: '#E0E0E0',
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 12,
  },
  resetDataButtonText: {
    color: '#2C2C2C',
    fontSize: 14,
    fontWeight: '600',
  },
});

export default PersonalizationMemoryScreen;