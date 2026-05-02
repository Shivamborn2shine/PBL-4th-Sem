/**
 * Observe4U – Firebase Configuration & Firestore Helpers
 *
 * Initializes Firebase and provides Firestore CRUD operations
 * for threat reports, graph nodes, and graph edges.
 */

// ═══════════════════════════════════════════════════════════════
// Firebase Configuration
// ═══════════════════════════════════════════════════════════════

const firebaseConfig = {
    apiKey: "AIzaSyAvS5fiaG19uNCGhgTcNbHIUkkAFNB7WBU",
    authDomain: "pbl-4th-sem.firebaseapp.com",
    projectId: "pbl-4th-sem",
    storageBucket: "pbl-4th-sem.firebasestorage.app",
    messagingSenderId: "131004359356",
    appId: "1:131004359356:web:eaa68f137b7fa52dc0e6b9",
    measurementId: "G-FEJMKF99GT"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);
const db = firebase.firestore();

// Collection references
const COLLECTIONS = {
    THREAT_REPORTS: 'threat_reports',
    GRAPH_NODES: 'graph_nodes',
    GRAPH_EDGES: 'graph_edges',
};

// ═══════════════════════════════════════════════════════════════
// Firestore Helper Functions
// ═══════════════════════════════════════════════════════════════

/**
 * Save a scan report to Firestore.
 */
async function firebaseSaveReport(report) {
    try {
        const docId = report.report_id || report.id || Date.now().toString();
        await db.collection(COLLECTIONS.THREAT_REPORTS).doc(docId).set({
            ...report,
            created_at: firebase.firestore.FieldValue.serverTimestamp(),
        });
        console.log('✅ Report saved to Firestore:', docId);
        return true;
    } catch (error) {
        console.error('❌ Firestore save report error:', error);
        return false;
    }
}

/**
 * Load all scan history from Firestore, ordered by timestamp descending.
 */
async function firebaseLoadHistory(limit = 50) {
    try {
        const snapshot = await db.collection(COLLECTIONS.THREAT_REPORTS)
            .orderBy('created_at', 'desc')
            .limit(limit)
            .get();

        const history = [];
        snapshot.forEach(doc => {
            history.push({ id: doc.id, ...doc.data() });
        });
        console.log(`✅ Loaded ${history.length} reports from Firestore`);
        return history;
    } catch (error) {
        console.error('❌ Firestore load history error:', error);
        return [];
    }
}

/**
 * Clear all scan history from Firestore.
 */
async function firebaseClearHistory() {
    try {
        const snapshot = await db.collection(COLLECTIONS.THREAT_REPORTS).get();
        const batch = db.batch();
        snapshot.forEach(doc => batch.delete(doc.ref));
        await batch.commit();
        console.log('✅ Firestore history cleared');
        return true;
    } catch (error) {
        console.error('❌ Firestore clear history error:', error);
        return false;
    }
}

/**
 * Save or update a graph node in Firestore.
 * Uses merge to increment scan_count on existing nodes.
 */
async function firebaseSaveGraphNode(nodeId, nodeType, label) {
    try {
        const docRef = db.collection(COLLECTIONS.GRAPH_NODES).doc(nodeId);
        const doc = await docRef.get();

        if (doc.exists) {
            await docRef.update({
                scan_count: firebase.firestore.FieldValue.increment(1),
                updated_at: firebase.firestore.FieldValue.serverTimestamp(),
            });
        } else {
            await docRef.set({
                node_id: nodeId,
                node_type: nodeType,
                label: label,
                scan_count: 1,
                created_at: firebase.firestore.FieldValue.serverTimestamp(),
                updated_at: firebase.firestore.FieldValue.serverTimestamp(),
            });
        }
        return true;
    } catch (error) {
        console.error('❌ Firestore save node error:', error);
        return false;
    }
}

/**
 * Save or update a graph edge in Firestore.
 */
async function firebaseSaveGraphEdge(source, target, relation) {
    try {
        const edgeId = `${source}__${target}`.replace(/[\/\.]/g, '_');
        const docRef = db.collection(COLLECTIONS.GRAPH_EDGES).doc(edgeId);
        const doc = await docRef.get();

        if (doc.exists) {
            await docRef.update({
                occurrence_count: firebase.firestore.FieldValue.increment(1),
                updated_at: firebase.firestore.FieldValue.serverTimestamp(),
            });
        } else {
            await docRef.set({
                source_node: source,
                target_node: target,
                relation_type: relation,
                occurrence_count: 1,
                created_at: firebase.firestore.FieldValue.serverTimestamp(),
                updated_at: firebase.firestore.FieldValue.serverTimestamp(),
            });
        }
        return true;
    } catch (error) {
        console.error('❌ Firestore save edge error:', error);
        return false;
    }
}

/**
 * Load all graph data (nodes + edges) from Firestore.
 */
async function firebaseLoadGraphData() {
    try {
        const nodesSnapshot = await db.collection(COLLECTIONS.GRAPH_NODES).get();
        const edgesSnapshot = await db.collection(COLLECTIONS.GRAPH_EDGES).get();

        const nodes = [];
        nodesSnapshot.forEach(doc => {
            const data = doc.data();
            nodes.push({
                id: data.node_id || doc.id,
                type: data.node_type,
                label: data.label || doc.id,
            });
        });

        const edges = [];
        edgesSnapshot.forEach(doc => {
            const data = doc.data();
            edges.push({
                source: data.source_node,
                target: data.target_node,
                relation: data.relation_type,
            });
        });

        console.log(`✅ Loaded graph: ${nodes.length} nodes, ${edges.length} edges`);
        return { nodes, edges };
    } catch (error) {
        console.error('❌ Firestore load graph error:', error);
        return { nodes: [], edges: [] };
    }
}

/**
 * Clear all graph data from Firestore.
 */
async function firebaseClearGraphData() {
    try {
        const nodeSnap = await db.collection(COLLECTIONS.GRAPH_NODES).get();
        const edgeSnap = await db.collection(COLLECTIONS.GRAPH_EDGES).get();
        const batch = db.batch();
        nodeSnap.forEach(doc => batch.delete(doc.ref));
        edgeSnap.forEach(doc => batch.delete(doc.ref));
        await batch.commit();
        console.log('✅ Firestore graph data cleared');
        return true;
    } catch (error) {
        console.error('❌ Firestore clear graph error:', error);
        return false;
    }
}

console.log('🔥 Firebase initialized for project:', firebaseConfig.projectId);
