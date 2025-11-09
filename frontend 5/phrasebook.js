import React from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  StatusBar,
  Image,
  Dimensions,
  SafeAreaView,
} from 'react-native';
import Footer from './Footer';

const { width, height } = Dimensions.get('window');

const PhrasebookScreen = () => {
  const handleAddPhrase = () => {
    console.log('Add phrase pressed');
    // Handle add phrase functionality
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="dark-content" backgroundColor="transparent" translucent={true} />

      {/* Background Curve Images */}
      <Image
        source={require('./assets/curve.png')}
        style={styles.curveImage1}
        resizeMode="contain"
      />
      <Image
        source={require('./assets/curve.png')}
        style={styles.curveImage2}
        resizeMode="contain"
      />
      <Image
        source={require('./assets/curve.png')}
        style={styles.curveImage3}
        resizeMode="contain"
      />

      {/* Main Content */}
      <View style={styles.content}>
        {/* Header */}
        <Text style={styles.title}>Your Phrasebook</Text>

        {/* Subtitle/Description */}
        <Text style={styles.subtitle}>
          Save, organize, and revisit your most-used phrases — tailored for your
          daily conversations, across any language.
        </Text>

        {/* --- HORIZONTAL LINE ADDED HERE --- */}
        <View style={styles.divider} />

        {/* Empty State Message */}
        <Text style={styles.emptyStateText}>
          No phrases yet — let's fix that!
        </Text>
      </View>

      {/* Add Button */}
      <TouchableOpacity style={styles.addButton} onPress={handleAddPhrase}>
        <Text style={styles.addButtonText}>+</Text>
      </TouchableOpacity>

      {/* Footer */}
      <Footer />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#F8F9FA',
  },
  content: {
    flex: 1,
    paddingHorizontal: 24,
    paddingTop: height * 0.1,
    justifyContent: 'flex-start',
    alignItems: 'center',
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#1A1A1A',
    marginBottom: 16,
    textAlign: 'center',
  },
  subtitle: {
    fontSize: 16,
    color: '#666666',
    lineHeight: 22,
    textAlign: 'center',
  },
  // --- STYLE FOR THE DIVIDER ---
  divider: {
    height: 2,
    width: '100%', // The line will span 80% of the container's width
    backgroundColor: '#E0E0E0', // A light gray color
    marginVertical: 30, // Adds space above and below the line
  },
  emptyStateText: {
    fontSize: 16,
    color: '#666666',
    textAlign: 'center',
  },
  addButton: {
    position: 'absolute',
    bottom: 409,
    alignSelf: 'center',
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: '#FFFFFF',
    borderWidth: 2,
    borderColor: '#666666',
    justifyContent: 'center',
    alignItems: 'center',
    
  },
  addButtonText: {
    fontSize: 30,
    color: '#666666',
    fontWeight: '400',
    lineHeight: 24,
    textAlign: 'center',
    includeFontPadding: false,
    textAlignVertical: 'center',
  },
  curveImage1: {
    position: 'absolute',
    width: 250,
    height: 250,
    top: height * 0.1,
    right: -width * 0.25,
    opacity: 0.2,
    transform: [{ rotate: '15deg' }],
  },
  curveImage2: {
    position: 'absolute',
    width: 200,
    height: 200,
    bottom: height * 0.15,
    left: -width * 0.2,
    opacity: 0.2,
    transform: [{ rotate: '-25deg' }],
  },
  curveImage3: {
    position: 'absolute',
    width: 220,
    height: 220,
    top: height * 0.5,
    right: -width * 0.3,
    opacity: 0.15,
    transform: [{ rotate: '-30deg' }],
  },
});

export default PhrasebookScreen;